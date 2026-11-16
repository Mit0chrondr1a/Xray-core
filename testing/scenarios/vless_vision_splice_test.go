package scenarios

import (
	"bytes"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	gonet "net"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/sync/errgroup"
)

// visionSplicePattern is a position-dependent byte stream, so any reordering or
// loss across the userspace -> splice handoff shows up as a mismatch.
func visionSplicePattern(offset, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		p := offset + i
		out[i] = byte(p*31 + p>>8)
	}
	return out
}

// startInnerTLS13Server serves a download-heavy exchange over real TLS 1.3:
// request = 8-byte download size + 4-byte upload size + upload bytes,
// response = the upload echoed back, then `download` pattern bytes.
func startInnerTLS13Server(t *testing.T) net.Destination {
	t.Helper()
	ct, _ := cert.MustGenerate(nil, cert.CommonName("inner.vision.test"))
	certPEM, keyPEM := ct.ToPEM()
	pair, err := gotls.X509KeyPair(certPEM, keyPEM)
	common.Must(err)

	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates: []gotls.Certificate{pair},
		MinVersion:   gotls.VersionTLS13,
	})
	common.Must(err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn gonet.Conn) {
				defer conn.Close()
				var header [12]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				download := int(binary.BigEndian.Uint64(header[:8]))
				upload := make([]byte, binary.BigEndian.Uint32(header[8:]))
				if _, err := io.ReadFull(conn, upload); err != nil {
					return
				}
				if _, err := conn.Write(upload); err != nil {
					return
				}
				const chunk = 64 << 10
				for sent := 0; sent < download; {
					n := min(chunk, download-sent)
					if _, err := conn.Write(visionSplicePattern(sent, n)); err != nil {
						return
					}
					sent += n
				}
			}(conn)
		}
	}()

	addr := ln.Addr().(*gonet.TCPAddr)
	return net.TCPDestination(net.LocalHostIP, net.Port(addr.Port))
}

func visionSpliceExchange(clientPort net.Port, download, upload int) func() error {
	return func() error {
		conn, err := gotls.DialWithDialer(&gonet.Dialer{Timeout: 10 * time.Second}, "tcp",
			fmt.Sprintf("127.0.0.1:%d", clientPort),
			&gotls.Config{InsecureSkipVerify: true, ServerName: "inner.vision.test", MinVersion: gotls.VersionTLS13})
		if err != nil {
			return fmt.Errorf("inner TLS dial: %w", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

		request := make([]byte, 12+upload)
		binary.BigEndian.PutUint64(request[:8], uint64(download))
		binary.BigEndian.PutUint32(request[8:12], uint32(upload))
		copy(request[12:], visionSplicePattern(7, upload))
		if _, err := conn.Write(request); err != nil {
			return fmt.Errorf("inner TLS write: %w", err)
		}

		echoed := make([]byte, upload)
		if _, err := io.ReadFull(conn, echoed); err != nil {
			return fmt.Errorf("read echoed upload: %w", err)
		}
		if !bytes.Equal(echoed, request[12:]) {
			return fmt.Errorf("uplink payload corrupted")
		}
		const chunk = 64 << 10
		got := make([]byte, chunk)
		for received := 0; received < download; {
			n := min(chunk, download-received)
			if _, err := io.ReadFull(conn, got[:n]); err != nil {
				return fmt.Errorf("read download at %d/%d: %w", received, download, err)
			}
			if !bytes.Equal(got[:n], visionSplicePattern(received, n)) {
				return fmt.Errorf("download corrupted or reordered near offset %d", received)
			}
			received += n
		}
		return nil
	}
}

func visionSpliceConfigs(serverPort, clientPort net.Port, dest net.Destination, serverStream, clientStream *internet.StreamConfig) (*core.Config, *core.Config) {
	userID := protocol.NewID(uuid.New())
	logApp := []*serial.TypedMessage{
		serial.ToTypedMessage(&log.Config{
			ErrorLogLevel: clog.Severity_Warning,
			ErrorLogType:  log.LogType_Console,
		}),
	}
	account := serial.ToTypedMessage(&vless.Account{Id: userID.String(), Flow: vless.XRV})

	serverConfig := &core.Config{
		App: logApp,
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList:       &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
				Listen:         net.NewIPOrDomain(net.LocalHostIP),
				StreamSettings: serverStream,
			}),
			ProxySettings: serial.ToTypedMessage(&inbound.Config{
				Users: []*protocol.User{{Account: account}},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	}
	clientConfig := &core.Config{
		App: logApp,
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(dest.Address),
				RewritePort:     uint32(dest.Port),
				AllowedNetworks: []net.Network{net.Network_TCP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: net.NewIPOrDomain(net.LocalHostIP),
					Port:    uint32(serverPort),
					User:    &protocol.User{Account: account},
				},
			}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: clientStream}),
		}},
	}
	return serverConfig, clientConfig
}

// runVisionSpliceScenario pushes real TLS 1.3 traffic through VLESS+Vision and
// checks two things: the stream is byte-exact end to end, and the server's
// response legs were handed to splice(2) once Vision switched to direct copy.
//
// The other Vision scenarios carry a non-TLS payload, so Vision never leaves
// padding mode there and neither the direct-copy switch nor the raw handoff is
// exercised. That gap hid a client-side "bad record MAC" regression.
func runVisionSpliceScenario(t *testing.T, serverStream, clientStream *internet.StreamConfig) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		t.Skip("splice is Linux-only")
	}
	dest := startInnerTLS13Server(t)
	serverPort := tcp.PickPort()
	clientPort := tcp.PickPort()
	serverConfig, clientConfig := visionSpliceConfigs(serverPort, clientPort, dest, serverStream, clientStream)

	// The server runs in this process so its splice counter is observable; the
	// client is a separate xray process built from the same tree.
	server, err := core.New(withDefaultApps(serverConfig))
	common.Must(err)
	common.Must(server.Start())
	defer server.Close()

	clients, err := InitializeServerConfigs(clientConfig)
	common.Must(err)
	defer CloseAllServers(clients)

	const flows = 4
	before := proxy.VisionGoTLSLaneSpliceFlows()
	var errg errgroup.Group
	for range flows {
		errg.Go(visionSpliceExchange(clientPort, 8<<20, 48<<10))
	}
	if err := errg.Wait(); err != nil {
		t.Fatal(err)
	}
	if got := proxy.VisionGoTLSLaneSpliceFlows() - before; got != flows {
		t.Fatalf("server spliced %d of %d Vision response legs; the Go TLS/REALITY inbound must splice after the direct-copy switch, as upstream does", got, flows)
	}
}

func TestVlessXtlsVisionSplicesResponseOnGoTLSInbound(t *testing.T) {
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	serverStream := &internet.StreamConfig{
		ProtocolName: "tcp",
		SecurityType: serial.GetMessageType(&tls.Config{}),
		SecuritySettings: []*serial.TypedMessage{
			serial.ToTypedMessage(&tls.Config{
				Certificate: []*tls.Certificate{tls.ParseCertificate(ct)},
			}),
		},
	}
	clientStream := &internet.StreamConfig{
		ProtocolName: "tcp",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(&transtcp.Config{}),
		}},
		SecurityType: serial.GetMessageType(&tls.Config{}),
		SecuritySettings: []*serial.TypedMessage{
			serial.ToTypedMessage(&tls.Config{
				PinnedPeerCertSha256: [][]byte{ctHash[:]},
			}),
		},
	}
	runVisionSpliceScenario(t, serverStream, clientStream)
}

func TestVlessXtlsVisionSplicesResponseOnGoRealityInbound(t *testing.T) {
	privateKey, _ := base64.RawURLEncoding.DecodeString("aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks")
	publicKey, _ := base64.RawURLEncoding.DecodeString("E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM")
	shortIds := [][]byte{make([]byte, 8)}
	hex.Decode(shortIds[0], []byte("0123456789abcdef"))

	serverStream := &internet.StreamConfig{
		ProtocolName: "tcp",
		SecurityType: serial.GetMessageType(&reality.Config{}),
		SecuritySettings: []*serial.TypedMessage{
			serial.ToTypedMessage(&reality.Config{
				Dest:        "www.google.com:443", // same external dest as TestVlessXtlsVisionReality
				ServerNames: []string{"www.google.com"},
				PrivateKey:  privateKey,
				ShortIds:    shortIds,
				Type:        "tcp",
			}),
		},
	}
	clientStream := &internet.StreamConfig{
		ProtocolName: "tcp",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(&transtcp.Config{}),
		}},
		SecurityType: serial.GetMessageType(&reality.Config{}),
		SecuritySettings: []*serial.TypedMessage{
			serial.ToTypedMessage(&reality.Config{
				Fingerprint: "chrome",
				ServerName:  "www.google.com",
				PublicKey:   publicKey,
				ShortId:     shortIds[0],
				SpiderX:     "/",
			}),
		},
	}
	runVisionSpliceScenario(t, serverStream, clientStream)
}
