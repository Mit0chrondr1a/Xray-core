package tls

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"

	utls "github.com/refraction-networking/utls"
	"google.golang.org/grpc/credentials"
)

// grpcUtlsInfo contains the auth information for a TLS authenticated connection.
// It implements the AuthInfo interface.
type grpcUtlsInfo struct {
	State utls.ConnectionState
	credentials.CommonAuthInfo
	// This API is experimental.
	SPIFFEID *url.URL
}

// AuthType returns the type of TLSInfo as a string.
func (t grpcUtlsInfo) AuthType() string {
	return "utls"
}

// GetSecurityValue returns security info requested by channelz.
func (t grpcUtlsInfo) GetSecurityValue() credentials.ChannelzSecurityValue {
	v := &credentials.TLSChannelzSecurityValue{
		StandardName: "0x" + strconv.FormatUint(uint64(t.State.CipherSuite), 16),
	}
	// Currently there's no way to get LocalCertificate info from tls package.
	if len(t.State.PeerCertificates) > 0 {
		v.RemoteCertificate = t.State.PeerCertificates[0].Raw
	}
	return v
}

// grpcUtls is the credentials required for authenticating a connection using TLS.
type grpcUtls struct {
	config      *gotls.Config
	fingerprint *utls.ClientHelloID
}

func (c grpcUtls) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
		ServerName:       c.config.ServerName,
	}
}

func (c *grpcUtls) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (_ net.Conn, _ credentials.AuthInfo, err error) {
	// use local cfg to avoid clobbering ServerName if using multiple endpoints
	cfg := c.config.Clone()
	if cfg.ServerName == "" {
		serverName, _, err := net.SplitHostPort(authority)
		if err != nil {
			// If the authority had no host port or if the authority cannot be parsed, use it as-is.
			serverName = authority
		}
		cfg.ServerName = serverName
	}
	conn := UClient(rawConn, cfg, c.fingerprint).(*UConn)
	errChannel := make(chan error, 1)
	go func() {
		errChannel <- conn.HandshakeContext(ctx)
		close(errChannel)
	}()
	select {
	case err := <-errChannel:
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
	case <-ctx.Done():
		conn.Close()
		return nil, nil, ctx.Err()
	}
	tlsInfo := grpcUtlsInfo{
		State: conn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
	}
	return conn, tlsInfo, nil
}

// ServerHandshake is not supported for uTLS (client-only). Returns an error.
func (c *grpcUtls) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("uTLS server handshake is not supported")
}

func (c *grpcUtls) Clone() credentials.TransportCredentials {
	return NewGrpcUtls(c.config, c.fingerprint)
}

func (c *grpcUtls) OverrideServerName(serverNameOverride string) error {
	c.config.ServerName = serverNameOverride
	return nil
}

// NewGrpcUtls uses c to construct a TransportCredentials based on uTLS.
func NewGrpcUtls(c *gotls.Config, fingerprint *utls.ClientHelloID) credentials.TransportCredentials {
	tc := &grpcUtls{c.Clone(), fingerprint}
	return tc
}
