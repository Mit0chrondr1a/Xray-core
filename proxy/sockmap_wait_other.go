//go:build !linux

package proxy

import "github.com/xtls/xray-core/common/net"

func waitForSockmapForwarding(readerConn, writerConn net.Conn) (fallback bool, obs sockmapForwardObservation, err error) {
	return true, sockmapForwardObservation{}, nil
}
