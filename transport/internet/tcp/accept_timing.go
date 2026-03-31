package tcp

import (
	"net"
	"sync"
)

var acceptStartByConn sync.Map

func recordAcceptStartUnixNano(conn net.Conn, unixNano int64) {
	if conn == nil || unixNano <= 0 {
		return
	}
	acceptStartByConn.Store(conn, unixNano)
}

// TakeAcceptStartUnixNano consumes the listener-side accept timestamp for conn.
// It returns 0 when no timestamp was recorded.
func TakeAcceptStartUnixNano(conn net.Conn) int64 {
	if conn == nil {
		return 0
	}
	if unixNano, ok := acceptStartByConn.LoadAndDelete(conn); ok {
		if ts, ok := unixNano.(int64); ok {
			return ts
		}
	}
	return 0
}
