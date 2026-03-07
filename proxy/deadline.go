package proxy

import (
	gonet "net"
	"time"

	"github.com/xtls/xray-core/transport/internet/splithttp"
)

// SetHandshakeReadDeadline applies a handshake/read deadline when the transport
// can support it. Non-raw split HTTP streams may truthfully report that read
// deadlines are unsupported; that limitation is not fatal for protocol setup.
func SetHandshakeReadDeadline(conn gonet.Conn, t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		if splithttp.IsDeadlineUnsupported(err) {
			return nil
		}
		return err
	}
	return nil
}

func ClearHandshakeReadDeadline(conn gonet.Conn) error {
	return SetHandshakeReadDeadline(conn, time.Time{})
}
