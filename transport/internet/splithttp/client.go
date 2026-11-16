package splithttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	IsClosed() bool

	// ctx, url, sessionId, body, uploadOnly
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)

	// ctx, url, sessionId, seqStr, body, contentLength
	PostPacket(context.Context, string, string, string, buf.MultiBuffer) error
}

// implements splithttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	transportConfig *Config
	client          *http.Client
	closed          atomic.Bool
	httpVersion     string
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *DefaultDialerClient) waitForPacketPostDispatch() bool {
	return c.httpVersion == "1.1"
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	// this is done when the TCP/UDP connection to the server was established,
	// and we can unblock the Dial function and print correct net addresses in
	// logs
	gotConn := done.New()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
			gotConn.Close()
		},
	})

	method := "GET" // stream-down
	if body != nil {
		method = c.transportConfig.GetNormalizedUplinkHTTPMethod() // stream-up/one
	}
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, body)
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to create HTTP request for "+url)
		return nil, nil, nil, err
	}
	c.transportConfig.FillStreamRequest(req, sessionId, "")

	wrc = &WaitReadCloser{Wait: make(chan struct{})}
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly { // stream-down is enough
				c.closed.Store(true)
				errors.LogInfoInner(ctx, err, "failed to "+method+" "+url)
			}
			gotConn.Close()
			common.Close(body)
			wrc.Close()
			return
		}
		if resp.StatusCode != 200 && !uploadOnly {
			errors.LogInfo(ctx, "unexpected status ", resp.StatusCode)
		}
		if resp.StatusCode != 200 || uploadOnly { // stream-up
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close() // if it is called immediately, the upload will be interrupted also
			common.Close(body)
			wrc.Close()
			return
		}
		wrc.(*WaitReadCloser).Set(resp.Body)
	}()

	<-gotConn.Wait()
	return
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, nil)
	if err != nil {
		return err
	}
	c.transportConfig.FillPacketRequest(req, sessionId, seqStr, payload)

	if c.httpVersion != "1.1" {
		resp, err := c.client.Do(req)
		if err != nil {
			c.closed.Store(true)
			return err
		}

		io.Copy(io.Discard, resp.Body)
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return errors.New("bad status code:", resp.Status)
		}
	} else {
		// stringify the entire HTTP/1.1 request so it can be
		// safely retried. if instead req.Write is called multiple
		// times, the body is already drained after the first
		// request
		requestBuff := new(bytes.Buffer)
		requestBuff.Grow(512 + int(req.ContentLength))
		common.Must(req.Write(requestBuff))

		var uploadConn any
		var h1UploadConn *H1Conn

		for {
			uploadConn = c.uploadRawPool.Get()
			newConnection := uploadConn == nil
			if newConnection {
				newConn, err := c.dialUploadConn(context.WithoutCancel(ctx))
				if err != nil {
					return err
				}
				h1UploadConn = NewH1Conn(newConn)
				uploadConn = h1UploadConn
			} else {
				h1UploadConn = uploadConn.(*H1Conn)

				// TODO: Replace 0 here with a config value later
				// Or add some other condition for optimization purposes
				if h1UploadConn.UnreadedResponsesCount > 0 {
					resp, err := http.ReadResponse(h1UploadConn.RespBufReader, req)
					if err != nil {
						_ = h1UploadConn.Close()
						c.closed.Store(true)
						return fmt.Errorf("error while reading response: %s", err.Error())
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					if closeErr := resp.Body.Close(); closeErr != nil {
						_ = h1UploadConn.Close()
						c.closed.Store(true)
						return fmt.Errorf("error while closing response body: %s", closeErr.Error())
					}
					if resp.StatusCode != 200 {
						_ = h1UploadConn.Close()
						return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
					}
				}
			}

			_, err := h1UploadConn.Write(requestBuff.Bytes())
			// if the write failed, we try another connection from
			// the pool, until the write on a new connection fails.
			// failed writes to a pooled connection are normal when
			// the connection has been closed in the meantime.
			if err == nil {
				break
			}
			_ = h1UploadConn.Close()
			if newConnection {
				return err
			}
		}

		c.uploadRawPool.Put(uploadConn)
	}

	return nil
}

// HTTP/1.1 and HTTP/2 will close itself, we only handle HTTP/3 here
func (c *DefaultDialerClient) Close() error {
	transport := c.client.Transport
	if h3Transport, ok := transport.(*http3.Transport); ok {
		h3Transport.Close()
	}
	return nil
}

type WaitReadCloser struct {
	Wait chan struct{}
	io.ReadCloser
	mu             sync.Mutex
	closed         bool
	readDeadline   time.Time
	deadlineSignal chan struct{}
	once           sync.Once
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		if rc != nil {
			_ = rc.Close()
		}
		w.once.Do(func() { close(w.Wait) })
		return
	}
	w.ReadCloser = rc
	if deadline := w.readDeadline; !deadline.IsZero() {
		_ = setSplitReadDeadline(rc, deadline)
	}
	w.mu.Unlock()
	w.once.Do(func() { close(w.Wait) })
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	for {
		w.mu.Lock()
		rc := w.ReadCloser
		closed := w.closed
		deadline := w.readDeadline
		signal := w.ensureDeadlineSignalLocked()
		w.mu.Unlock()
		if rc != nil {
			return rc.Read(b)
		}
		if closed {
			return 0, io.ErrClosedPipe
		}
		if deadline.IsZero() {
			select {
			case <-w.Wait:
			case <-signal:
			}
			continue
		}
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return 0, errSplitDeadlineExceeded
		}
		timer := time.NewTimer(timeout)
		select {
		case <-w.Wait:
			if !timer.Stop() {
				<-timer.C
			}
		case <-signal:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			return 0, errSplitDeadlineExceeded
		}
	}
}

func (w *WaitReadCloser) Close() error {
	w.mu.Lock()
	w.closed = true
	rc := w.ReadCloser
	w.ReadCloser = nil
	w.mu.Unlock()
	w.once.Do(func() { close(w.Wait) })
	if rc != nil {
		return rc.Close()
	}
	return nil
}

func (w *WaitReadCloser) SetDeadline(t time.Time) error {
	return w.SetReadDeadline(t)
}

func (w *WaitReadCloser) SetReadDeadline(t time.Time) error {
	w.mu.Lock()
	w.readDeadline = t
	signal := w.ensureDeadlineSignalLocked()
	w.deadlineSignal = make(chan struct{})
	rc := w.ReadCloser
	w.mu.Unlock()
	close(signal)
	if rc != nil {
		return setSplitReadDeadline(rc, t)
	}
	return nil
}

func (w *WaitReadCloser) ensureDeadlineSignalLocked() chan struct{} {
	if w.deadlineSignal == nil {
		w.deadlineSignal = make(chan struct{})
	}
	return w.deadlineSignal
}
