package tcp

import (
	"context"
	gotls "crypto/tls"
	"slices"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var rustClientWithTimeoutFn = tls.RustClientWithTimeout
var nativeAvailableFn = native.Available
var nativeFullKTLSSupportedForTLSConfigFn = tls.NativeFullKTLSSupportedForTLSConfig

func nativeHandshakeTimeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			return remaining
		}
		// Deadline already expired; fail fast in native handshake path.
		return time.Millisecond
	}
	return 0
}

func rustClientWithContext(ctx context.Context, conn net.Conn, config *tls.Config, dest net.Destination) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	timeout := nativeHandshakeTimeoutFromContext(ctx)
	// Ensure cancellation can interrupt the native blocking handshake early.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	defer close(done)
	// Always clear temporary handshake deadlines so they never leak into
	// steady-state reads/writes.
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
	}

	return rustClientWithTimeoutFn(conn, config, dest, timeout)
}

func shouldUseNativeTLSClient(config *tls.Config) bool {
	return nativeAvailableFn() && nativeFullKTLSSupportedForTLSConfigFn(config)
}

func nativeTLSConfigWithRuntimeOverrides(config *tls.Config, tlsConfig *gotls.Config) *tls.Config {
	if config == nil {
		return nil
	}
	if tlsConfig == nil {
		return config
	}

	nativeConfig := *config
	nativeConfig.ServerName = tlsConfig.ServerName
	nativeConfig.NextProtocol = slices.Clone(tlsConfig.NextProtos)
	if r, ok := tlsConfig.Rand.(*tls.RandCarrier); ok {
		nativeConfig.VerifyPeerCertByName = slices.Clone(r.VerifyPeerCertByName)
	}
	return &nativeConfig
}

// Dial dials a new TCP connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "dialing TCP to ", dest)
	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		mitmServerName := session.MitmServerNameFromContext(ctx)
		mitmAlpn11 := session.MitmAlpn11FromContext(ctx)
		var tlsConfig *gotls.Config
		if tls.IsFromMitm(config.ServerName) {
			tlsConfig = config.GetTLSConfig(tls.WithOverrideName(mitmServerName))
		} else {
			tlsConfig = config.GetTLSConfig(tls.WithDestination(dest))
		}
		nativeTLSConfig := nativeTLSConfigWithRuntimeOverrides(config, tlsConfig)
		dnsFlowClass := session.ResolveDNSFlowClass(ctx)

		isFromMitmVerify := false
		if r, ok := tlsConfig.Rand.(*tls.RandCarrier); ok && len(r.VerifyPeerCertByName) > 0 {
			for i, name := range r.VerifyPeerCertByName {
				if tls.IsFromMitm(name) {
					isFromMitmVerify = true
					r.VerifyPeerCertByName[0], r.VerifyPeerCertByName[i] = r.VerifyPeerCertByName[i], r.VerifyPeerCertByName[0]
					r.VerifyPeerCertByName = r.VerifyPeerCertByName[1:]
					after := mitmServerName
					for {
						if len(after) > 0 {
							r.VerifyPeerCertByName = append(r.VerifyPeerCertByName, after)
						}
						_, after, _ = strings.Cut(after, ".")
						if !strings.Contains(after, ".") {
							break
						}
					}
					slices.Reverse(r.VerifyPeerCertByName)
					break
				}
			}
		}
		isFromMitmAlpn := len(tlsConfig.NextProtos) == 1 && tls.IsFromMitm(tlsConfig.NextProtos[0])
		if isFromMitmAlpn {
			if mitmAlpn11 {
				tlsConfig.NextProtos[0] = "http/1.1"
			} else {
				tlsConfig.NextProtos = []string{"h2", "http/1.1"}
			}
		}
		if fingerprint := tls.GetFingerprint(config.Fingerprint); fingerprint != nil {
			conn = tls.UClient(conn, tlsConfig, fingerprint)
			if len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "http/1.1" { // allow manually specify
				err = conn.(*tls.UConn).WebsocketHandshakeContext(ctx)
			} else {
				err = conn.(*tls.UConn).HandshakeContext(ctx)
			}
		} else if shouldUseNativeTLSClient(nativeTLSConfig) &&
			!session.VisionFlowFromContext(ctx) &&
			dnsFlowClass != session.DNSFlowClassTCPControl {
			conn, err = rustClientWithContext(ctx, conn, nativeTLSConfig, dest)
		} else {
			if shouldUseNativeTLSClient(nativeTLSConfig) {
				if session.VisionFlowFromContext(ctx) {
					errors.LogDebug(ctx, "Rust native TLS client skipped: Vision flow active — kTLS incompatible")
				} else if dnsFlowClass == session.DNSFlowClassTCPControl {
					errors.LogDebug(ctx, "Rust native TLS client skipped: DNS TCP control-plane flow")
				}
			}
			conn = tls.Client(conn, tlsConfig)
			if session.VisionFlowFromContext(ctx) || dnsFlowClass == session.DNSFlowClassTCPControl {
				// Vision flows and DNS control paths are latency-sensitive and
				// short-lived; skip kTLS promotion to avoid kernel handover
				// stalls/cork-pop on small early packets.
				err = conn.(*tls.Conn).HandshakeContext(ctx)
			} else {
				err = conn.(*tls.Conn).HandshakeAndEnableKTLS(ctx)
			}
		}
		if err != nil {
			if isFromMitmVerify {
				return nil, errors.New("MITM freedom RAW TLS: failed to verify Domain Fronting certificate from " + mitmServerName).Base(err).AtWarning()
			}
			return nil, err
		}
		negotiatedProtocol := conn.(tls.Interface).NegotiatedProtocol()
		if isFromMitmAlpn && !mitmAlpn11 && negotiatedProtocol != "h2" {
			conn.Close()
			return nil, errors.New("MITM freedom RAW TLS: unexpected Negotiated Protocol (" + negotiatedProtocol + ") with " + mitmServerName).AtWarning()
		}
	} else if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		if conn, err = reality.UClient(conn, config, ctx, dest); err != nil {
			return nil, err
		}
	}

	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("failed to get header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("failed to create header authenticator").Base(err).AtError()
		}
		conn = auth.Client(conn)
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
