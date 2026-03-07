package inbound

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

type bufferingRecorderConn struct {
	bytes.Buffer
	deadlines []time.Time
}

func (c *bufferingRecorderConn) Read([]byte) (int, error)        { return 0, nil }
func (c *bufferingRecorderConn) Close() error                    { return nil }
func (c *bufferingRecorderConn) LocalAddr() net.Addr             { return testAddr("local") }
func (c *bufferingRecorderConn) RemoteAddr() net.Addr            { return testAddr("remote") }
func (c *bufferingRecorderConn) SetDeadline(time.Time) error     { return nil }
func (c *bufferingRecorderConn) SetReadDeadline(time.Time) error { return nil }
func (c *bufferingRecorderConn) SetWriteDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	return nil
}

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

func TestDeferredVisionResponseHeaderFlushesOnFirstBodyWrite(t *testing.T) {
	conn := &bufferingRecorderConn{}
	writer := buf.NewBufferedWriter(buf.NewWriter(conn))
	request := &protocol.RequestHeader{Version: 1}

	if err := encoding.EncodeResponseHeader(writer, request, &encoding.Addons{}); err != nil {
		t.Fatalf("EncodeResponseHeader() error = %v", err)
	}
	if conn.Len() != 0 {
		t.Fatalf("buffered header should not be flushed yet, got %d bytes", conn.Len())
	}

	writer.SetFlushNext()

	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ok"))}); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}

	if got := conn.Bytes(); !bytes.Equal(got, []byte{1, 0, 'o', 'k'}) {
		t.Fatalf("flushed bytes = %v, want %v", got, []byte{1, 0, 'o', 'k'})
	}
	if len(conn.deadlines) != 0 {
		t.Fatalf("SetWriteDeadline calls = %d, want 0", len(conn.deadlines))
	}
}
