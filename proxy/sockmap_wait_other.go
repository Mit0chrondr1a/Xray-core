//go:build !linux

package proxy

import "github.com/xtls/xray-core/common/net"

func waitForSockmapForwarding(readerConn, writerConn net.Conn) (fallback bool, err error) {
	return true, nil
}
