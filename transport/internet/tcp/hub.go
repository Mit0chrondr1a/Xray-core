package tcp

import (
	"context"
	gotls "crypto/tls"
	"strings"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Listener is an internet.Listener that listens for TCP connections.
type Listener struct {
	listener      net.Listener
	tlsConfig     *gotls.Config
	tlsXrayConfig *tls.Config
	realityConfig *goreality.Config
	authConfig    internet.ConnectionAuthenticator
	config        *Config
	addConn       internet.ConnHandler
}

const tlsHandshakeTimeout = 8 * time.Second

// ListenTCP creates a new Listener based on configurations.
func ListenTCP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn: handler,
	}
	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = tcpSettings
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
		streamSettings.SocketSettings.AcceptProxyProtocol = l.config.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol
	}
	var listener net.Listener
	var err error
	if port == net.Port(0) { // unix
		if !address.Family().IsDomain() {
			return nil, errors.New("invalid unix listen: ", address).AtError()
		}
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen Unix Domain Socket on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening Unix Domain Socket on ", address)
	} else {
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP on ", address, ":", port)
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		errors.LogWarning(ctx, "accepting PROXY protocol")
	}

	l.listener = listener

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		l.tlsConfig = config.GetTLSConfig()
		l.tlsXrayConfig = config
	}
	if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		l.realityConfig = config.GetREALITYConfig()
		go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
	}

	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("invalid header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("invalid header settings.").Base(err).AtError()
		}
		l.authConfig = auth
	}

	go l.keepAccepting()
	return l, nil
}

func (v *Listener) keepAccepting() {
	for {
		conn, err := v.listener.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "failed to accepted raw connections")
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}
		go func(rawConn net.Conn) {
			conn := rawConn
			if v.tlsConfig != nil {
				if native.Available() && v.tlsXrayConfig != nil {
					if err := conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
						errors.LogWarningInner(context.Background(), err, "failed to set Rust TLS handshake deadline on accepted connection")
						_ = conn.Close()
						return
					}
					rustConn, tlsErr := tls.RustServer(conn, v.tlsXrayConfig)
					if err := conn.SetDeadline(time.Time{}); err != nil {
						errors.LogWarningInner(context.Background(), err, "failed to clear Rust TLS handshake deadline on accepted connection")
					}
					if tlsErr != nil {
						errors.LogWarningInner(context.Background(), tlsErr, "failed Rust TLS handshake on accepted connection")
						_ = conn.Close()
						return
					}
					conn = rustConn
				} else {
					tlsConn := tls.Server(conn, v.tlsConfig)
					if err := tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
						errors.LogWarningInner(context.Background(), err, "failed to set TLS handshake deadline on accepted connection")
						_ = tlsConn.Close()
						return
					}
					hsCtx, cancel := context.WithTimeout(context.Background(), tlsHandshakeTimeout)
					hsErr := tlsConn.(*tls.Conn).HandshakeAndEnableKTLS(hsCtx)
					cancel()
					if err := tlsConn.SetDeadline(time.Time{}); err != nil {
						errors.LogWarningInner(context.Background(), err, "failed to clear TLS handshake deadline on accepted connection")
					}
					if hsErr != nil {
						errors.LogWarningInner(context.Background(), hsErr, "failed TLS handshake on accepted connection")
						_ = tlsConn.Close()
						return
					}
					conn = tlsConn
				}
			} else if v.realityConfig != nil {
				realityConn, serveErr := reality.Server(conn, v.realityConfig)
				if serveErr != nil {
					errors.LogInfo(context.Background(), serveErr.Error())
					_ = conn.Close()
					return
				}
				conn = realityConn
			}
			if v.authConfig != nil {
				conn = v.authConfig.Server(conn)
			}
			v.addConn(stat.Connection(conn))
		}(conn)
	}
}

// Addr implements internet.Listener.Addr.
func (v *Listener) Addr() net.Addr {
	return v.listener.Addr()
}

// Close implements internet.Listener.Close.
func (v *Listener) Close() error {
	return v.listener.Close()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenTCP))
}
