package websocket

import (
	"context"
	"io"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
)

var _ buf.Writer = (*connection)(nil)

// connection is a wrapper for net.Conn over WebSocket connection.
// remoteAddr is used to pass "virtual" remote IP addresses in X-Forwarded-For.
// so we shouldn't directly read it form conn.
type connection struct {
	conn       *websocket.Conn
	reader     io.Reader
	remoteAddr net.Addr
	done       chan struct{}
	closeOnce  sync.Once
}

func NewConnection(conn *websocket.Conn, remoteAddr net.Addr, extraReader io.Reader, heartbeatPeriod uint32) *connection {
	c := &connection{
		conn:       conn,
		remoteAddr: remoteAddr,
		reader:     extraReader,
		done:       make(chan struct{}),
	}

	if heartbeatPeriod != 0 {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					errors.LogError(context.Background(), "panic in WebSocket heartbeat goroutine: ", r, "\n", string(debug.Stack()))
				}
			}()
			ticker := time.NewTicker(time.Duration(heartbeatPeriod) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-c.done:
					return
				case <-ticker.C:
					if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(5*time.Second)); err != nil {
						return
					}
				}
			}
		}()
	}

	return c
}

// Read implements net.Conn.Read()
func (c *connection) Read(b []byte) (int, error) {
	for {
		reader, err := c.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if errors.Cause(err) == io.EOF {
			c.reader = nil
			continue
		}
		return nBytes, err
	}
}

func (c *connection) getReader() (io.Reader, error) {
	if c.reader != nil {
		return c.reader, nil
	}

	_, reader, err := c.conn.NextReader()
	if err != nil {
		return nil, err
	}
	c.reader = reader
	return reader, nil
}

// Write implements io.Writer.
func (c *connection) Write(b []byte) (int, error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *connection) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *connection) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	var errs []interface{}
	if err := c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5)); err != nil {
		errs = append(errs, err)
	}
	if err := c.conn.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.New("failed to close connection").Base(errors.New(serial.Concat(errs...)))
	}
	return nil
}

func (c *connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *connection) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
