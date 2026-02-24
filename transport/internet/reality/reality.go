package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

type Conn struct {
	*reality.Conn
}

var (
	maxRealitySpiderResponseBytes int64 = 1 * 1024 * 1024
	maxRealitySpiderPaths               = 4096
	maxRealitySpiderSNIs                = 256 // max distinct SNI entries in spider map
	maxSpiderConcurrency                = 4
	spiderSemaphore                     = make(chan struct{}, 8)  // max 8 concurrent Spider sessions globally
	spiderThreadSem                     = make(chan struct{}, 16) // max 16 concurrent Spider crawling goroutines globally
	spiderSessionTimeout                = 30 * time.Second
)

func readSpiderBody(reader io.Reader) ([]byte, error) {
	return buf.ReadAllLimitedToBytes(reader, maxRealitySpiderResponseBytes)
}

func addSpiderPaths(paths map[string]struct{}, body []byte, prefix []byte) {
	for _, m := range href.FindAllSubmatch(body, -1) {
		if len(paths) >= maxRealitySpiderPaths {
			return
		}
		m[1] = bytes.TrimPrefix(m[1], prefix)
		if !bytes.Contains(m[1], dot) {
			paths[string(m[1])] = struct{}{}
		}
	}
}

func (c *Conn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

func Server(c net.Conn, config *reality.Config) (net.Conn, error) {
	realityConn, err := reality.Server(context.Background(), c, config)
	return &Conn{Conn: realityConn}, err
}

type UConn struct {
	*utls.UConn
	Config     *Config
	ServerName string
	AuthKey    []byte
	Verified   bool
}

func (c *UConn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

func (c *UConn) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c.Config.Show {
		localAddr := c.LocalAddr().String()
		errors.LogDebug(context.Background(), "REALITY localAddr: ", localAddr, "\tis using X25519MLKEM768 for TLS' communication: ", c.HandshakeState.ServerHello.ServerShare.Group == utls.X25519MLKEM768)
		errors.LogDebug(context.Background(), "REALITY localAddr: ", localAddr, "\tis using ML-DSA-65 for cert's extra verification: ", len(c.Config.Mldsa65Verify) > 0)
	}
	// Access the private peerCertificates field via unsafe+reflect.
	// This is fragile: any utls version that reorders fields will break the offset.
	// Tested against utls v0.0.12+ (github.com/refraction-networking/utls).
	// The recover() guard prevents silent memory corruption if the layout changes.
	certs, certsOk := func() (certs []*x509.Certificate, ok bool) {
		defer func() {
			if r := recover(); r != nil {
				errors.LogError(context.Background(), "REALITY: failed to access peerCertificates via unsafe (utls layout changed?): ", r)
			}
		}()
		p, found := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
		if !found {
			return nil, false
		}
		return *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset)), true
	}()
	if !certsOk || len(certs) == 0 {
		return errors.New("REALITY: unable to extract peer certificates")
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if hmac.Equal(h.Sum(nil), certs[0].Signature) {
			if len(c.Config.Mldsa65Verify) > 0 {
				if len(certs[0].Extensions) > 0 {
					h.Write(c.HandshakeState.Hello.Raw)
					h.Write(c.HandshakeState.ServerHello.Raw)
					verify, _ := mldsa65.Scheme().UnmarshalBinaryPublicKey(c.Config.Mldsa65Verify)
					if mldsa65.Verify(verify.(*mldsa65.PublicKey), h.Sum(nil), nil, certs[0].Extensions[0].Value) {
						c.Verified = true
						return nil
					}
				}
			} else {
				c.Verified = true
				return nil
			}
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

func UClient(c net.Conn, config *Config, ctx context.Context, dest net.Destination) (net.Conn, error) {
	localAddr := c.LocalAddr().String()
	uConn := &UConn{
		Config: config,
	}
	utlsConfig := &utls.Config{
		VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
		ServerName:             config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		KeyLogWriter:           KeyLogWriterFromConfig(config),
	}
	if utlsConfig.ServerName == "" {
		utlsConfig.ServerName = dest.Address.String()
	}
	uConn.ServerName = utlsConfig.ServerName
	fingerprint := tls.GetFingerprint(config.Fingerprint)
	if fingerprint == nil {
		return nil, errors.New("REALITY: failed to get fingerprint").AtError()
	}
	uConn.UConn = utls.UClient(c, utlsConfig, *fingerprint)
	{
		uConn.BuildHandshakeState()
		hello := uConn.HandshakeState.Hello
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
		hello.SessionId[0] = core.Version_x
		hello.SessionId[1] = core.Version_y
		hello.SessionId[2] = core.Version_z
		hello.SessionId[3] = 0 // reserved
		binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
		copy(hello.SessionId[8:], config.ShortId)
		if config.Show {
			errors.LogDebug(ctx, "REALITY localAddr: ", localAddr, "\thello.SessionId[:16]: ", hello.SessionId[:16])
		}
		publicKey, err := ecdh.X25519().NewPublicKey(config.PublicKey)
		if err != nil {
			return nil, errors.New("REALITY: publicKey == nil")
		}
		ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
		if ecdhe == nil {
			ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
		}
		if ecdhe == nil {
			return nil, errors.New("Current fingerprint ", uConn.ClientHelloID.Client, uConn.ClientHelloID.Version, " does not support TLS 1.3, REALITY handshake cannot establish.")
		}
		uConn.AuthKey, _ = ecdhe.ECDH(publicKey)
		if uConn.AuthKey == nil {
			return nil, errors.New("REALITY: SharedKey == nil")
		}
		if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
			return nil, err
		}
		aead := crypto.NewAesGcm(uConn.AuthKey)
		if config.Show {
			errors.LogDebug(ctx, "REALITY localAddr: ", localAddr, "\tAuthKey derived\tAEAD: ", fmt.Sprintf("%T", aead))
		}
		aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
	}
	// Try Rust native path only when full bidirectional kTLS is available and
	// no extra ML-DSA verification is configured.
	if native.Available() && tls.NativeFullKTLSSupported() && len(config.Mldsa65Verify) == 0 {
		ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
		if ecdhe == nil {
			ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
		}
		if ecdhe != nil {
			fd, fdErr := tls.ExtractFd(c)
			if fdErr == nil {
				realityCfg := native.RealityConfigNew(true)
				if realityCfg != nil {
					defer native.RealityConfigFree(realityCfg)
					native.RealityConfigSetServerPubkey(realityCfg, config.PublicKey)
					native.RealityConfigSetShortId(realityCfg, config.ShortId)
					native.RealityConfigSetVersion(realityCfg, core.Version_x, core.Version_y, core.Version_z)
					result, rustErr := native.RealityClientConnect(fd, uConn.HandshakeState.Hello.Raw, ecdhe.Bytes(), realityCfg)
					if rustErr == nil {
						if result != nil && result.KtlsTx && result.KtlsRx {
							return tls.NewRustConnChecked(c, result, uConn.ServerName)
						}
						// Handshake succeeded but kTLS incomplete — socket data
						// already consumed by Rust TLS engine, Go/uTLS fallback
						// would attempt a second handshake and fail.
						if result != nil && result.StateHandle != nil {
							native.TlsStateFree(result.StateHandle)
						}
						return nil, errors.New("REALITY: Rust handshake succeeded but kTLS incomplete")
					}
					// Rust native client path may have already consumed socket bytes.
					// Do not fall back to Go/uTLS on this same connection.
					return nil, rustErr
				}
			}
		}
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	// Zero auth key — no longer needed after handshake verification
	for i := range uConn.AuthKey {
		uConn.AuthKey[i] = 0
	}
	uConn.AuthKey = nil
	if config.Show {
		errors.LogDebug(ctx, "REALITY localAddr: ", localAddr, "\tuConn.Verified: ", uConn.Verified)
	}
	if !uConn.Verified {
		errors.LogError(ctx, "REALITY: received real certificate (potential MITM or redirection)")
		go func() {
			// Limit global concurrent Spider sessions to prevent DoS amplification.
			select {
			case spiderSemaphore <- struct{}{}:
				defer func() { <-spiderSemaphore }()
			default:
				uConn.Close()
				return
			}
			defer uConn.Close()

			spiderCtx, cancel := context.WithTimeout(context.Background(), spiderSessionTimeout)
			defer cancel()

			client := &http.Client{
				Timeout: spiderSessionTimeout,
				Transport: &http2.Transport{
					DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
						if config.Show {
							errors.LogDebug(ctx, "REALITY localAddr: ", localAddr, "\tDialTLSContext")
						}
						return uConn, nil
					},
				},
			}
			prefix := []byte("https://" + uConn.ServerName)
			maps.Lock()
			if maps.maps == nil {
				maps.maps = make(map[string]map[string]struct{})
			}
			paths := maps.maps[uConn.ServerName]
			if paths == nil {
				if len(maps.maps) >= maxRealitySpiderSNIs {
					maps.Unlock()
					uConn.Close()
					return
				}
				paths = make(map[string]struct{})
				paths[config.SpiderX] = struct{}{}
				maps.maps[uConn.ServerName] = paths
			}
			firstURL := string(prefix) + getPathLocked(paths)
			maps.Unlock()
			get := func(first bool) {
				var (
					req  *http.Request
					resp *http.Response
					err  error
					body []byte
				)
				if first {
					req, _ = http.NewRequestWithContext(spiderCtx, "GET", firstURL, nil)
				} else {
					maps.Lock()
					req, _ = http.NewRequestWithContext(spiderCtx, "GET", string(prefix)+getPathLocked(paths), nil)
					maps.Unlock()
				}
				if req == nil {
					return
				}
				req.Header.Set("User-Agent", utils.ChromeUA)
				if first && config.Show {
					errors.LogDebug(spiderCtx, "REALITY localAddr: ", localAddr, "\treq.UserAgent(): ", req.UserAgent())
				}
				times := 1
				if !first {
					times = int(crypto.RandBetween(config.SpiderY[4], config.SpiderY[5]))
				}
				for j := 0; j < times; j++ {
					if spiderCtx.Err() != nil {
						break
					}
					if !first && j == 0 {
						req.Header.Set("Referer", firstURL)
					}
					req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(crypto.RandBetween(config.SpiderY[0], config.SpiderY[1])))})
					if resp, err = client.Do(req); err != nil {
						break
					}
					body, err = readSpiderBody(resp.Body)
					resp.Body.Close()
					if err != nil {
						break
					}
					req.Header.Set("Referer", req.URL.String())
					maps.Lock()
					addSpiderPaths(paths, body, prefix)
					req.URL.Path = getPathLocked(paths)
					if config.Show {
						errors.LogDebug(spiderCtx, "REALITY localAddr: ", localAddr, "\treq.Referer(): ", req.Referer())
						errors.LogDebug(spiderCtx, "REALITY localAddr: ", localAddr, "\tlen(body): ", len(body))
						errors.LogDebug(spiderCtx, "REALITY localAddr: ", localAddr, "\tlen(paths): ", len(paths))
					}
					maps.Unlock()
					if !first {
						time.Sleep(time.Duration(crypto.RandBetween(config.SpiderY[6], config.SpiderY[7])) * time.Millisecond) // interval
					}
				}
			}
			// Gate initial crawl through global thread semaphore.
			select {
			case spiderThreadSem <- struct{}{}:
				get(true)
				<-spiderThreadSem
			default:
				// Global thread limit reached; skip initial crawl.
			}
			concurrency := int(crypto.RandBetween(config.SpiderY[2], config.SpiderY[3]))
			if concurrency > maxSpiderConcurrency {
				concurrency = maxSpiderConcurrency
			}
			var wg sync.WaitGroup
			for i := 0; i < concurrency; i++ {
				select {
				case spiderThreadSem <- struct{}{}:
				default:
					continue // global thread limit reached
				}
				wg.Add(1)
				go func() {
					defer func() { <-spiderThreadSem }()
					defer wg.Done()
					get(false)
				}()
			}
			wg.Wait()
		}()
		time.Sleep(time.Duration(crypto.RandBetween(config.SpiderY[8], config.SpiderY[9])) * time.Millisecond) // return
		return nil, errors.New("REALITY: processed invalid connection").AtWarning()
	}
	return uConn, nil
}

var (
	href = regexp.MustCompile(`href="([/h].*?)"`)
	dot  = []byte(".")
)

var maps struct {
	sync.Mutex
	maps map[string]map[string]struct{}
}

func getPathLocked(paths map[string]struct{}) string {
	stopAt := int(crypto.RandBetween(0, int64(len(paths)-1)))
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}
