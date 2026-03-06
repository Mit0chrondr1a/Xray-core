package tls

import (
	"context"
	gotl "crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// connectionStater mirrors net/http's detection interface.
type connectionStater interface {
	ConnectionState() gotl.ConnectionState
}

type connWithState struct {
	net.Conn
	state gotl.ConnectionState
}

func (c *connWithState) ConnectionState() gotl.ConnectionState {
	return c.state
}

type wrappedListener struct {
	net.Listener
}

func (l *wrappedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewKTLSPlaintextConn(&connWithState{
		Conn:  conn,
		state: gotl.ConnectionState{ServerName: "example.com"},
	}), nil
}

func TestKTLSPlaintextConnDoesNotExposeConnectionState(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	wantState := gotl.ConnectionState{ServerName: "example.com"}
	wrapped := &connWithState{Conn: c1, state: wantState}

	pc := NewKTLSPlaintextConn(wrapped)

	if _, ok := interface{}(pc).(connectionStater); ok {
		t.Fatal("KTLSPlaintextConn should not satisfy connectionStater")
	}
	if got := pc.TLSState().ServerName; got != wantState.ServerName {
		t.Fatalf("TLSState().ServerName=%q, want %q", got, wantState.ServerName)
	}
}

func TestKTLSPlaintextConnEnablesH2CDispatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	type observedRequest struct {
		path       string
		proto      string
		protoMajor int
		tlsNil     bool
	}
	observed := make(chan observedRequest, 1)

	serverProtocols := new(http.Protocols)
	serverProtocols.SetHTTP1(true)
	serverProtocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Protocols: serverProtocols,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			observed <- observedRequest{
				path:       r.URL.Path,
				proto:      r.Proto,
				protoMajor: r.ProtoMajor,
				tlsNil:     r.TLS == nil,
			}
			_, _ = w.Write([]byte("ok"))
		}),
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(&wrappedListener{Listener: ln})
	}()

	clientProtocols := new(http.Protocols)
	clientProtocols.SetUnencryptedHTTP2(true)
	client := &http.Client{
		Transport: &http.Transport{
			Protocols: clientProtocols,
		},
		Timeout: 5 * time.Second,
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get("http://" + ln.Addr().String() + "/Authent1cator/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read response failed: %v", err)
	}

	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 response, got %s", resp.Proto)
	}

	select {
	case got := <-observed:
		if got.path != "/Authent1cator/" {
			t.Fatalf("handler path=%q, want %q", got.path, "/Authent1cator/")
		}
		if got.protoMajor != 2 {
			t.Fatalf("handler proto major=%d, want 2 (proto=%q)", got.protoMajor, got.proto)
		}
		if !got.tlsNil {
			t.Fatal("expected plaintext request semantics (Request.TLS=nil)")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for handler observation")
	}

	select {
	case serveErr := <-serveDone:
		if serveErr != nil && serveErr != http.ErrServerClosed {
			t.Fatalf("server exited unexpectedly: %v", serveErr)
		}
	default:
	}
}
