package mux

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type Server struct {
	dispatcher routing.Dispatcher
}

// NewServer creates a new mux.Server.
func NewServer(ctx context.Context) *Server {
	s := &Server{}
	core.RequireFeatures(ctx, func(d routing.Dispatcher) {
		s.dispatcher = d
	})
	return s
}

// Type implements common.HasType.
func (s *Server) Type() interface{} {
	return s.dispatcher.Type()
}

// Dispatch implements routing.Dispatcher
func (s *Server) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.Dispatch(ctx, dest)
	}

	opts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)

	_, err := NewServerWorker(ctx, s.dispatcher, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})
	if err != nil {
		return nil, err
	}

	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

// DispatchLink implements routing.Dispatcher
func (s *Server) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.DispatchLink(ctx, dest, link)
	}
	worker, err := NewServerWorker(ctx, s.dispatcher, link)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-worker.done.Wait():
	}
	return nil
}

// Start implements common.Runnable.
func (s *Server) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *Server) Close() error {
	return nil
}

type ServerWorker struct {
	dispatcher      routing.Dispatcher
	link            *transport.Link
	sessionManager  *SessionManager
	done            *done.Instance
	timer           *time.Ticker
	createdAt       time.Time
	lastActivity    time.Time
	firstFrameAt    time.Time
	frameCount      int64
	sessionsCreated int64
}

var activeMuxParents int64

func NewServerWorker(ctx context.Context, d routing.Dispatcher, link *transport.Link) (*ServerWorker, error) {
	now := time.Now()
	worker := &ServerWorker{
		dispatcher:     d,
		link:           link,
		sessionManager: NewSessionManager(),
		done:           done.New(),
		timer:          time.NewTicker(60 * time.Second),
		createdAt:      now,
		lastActivity:   now,
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonSecurityGuard)
	}
	go worker.run(ctx)
	go worker.monitor()
	return worker, nil
}

func handle(ctx context.Context, s *Session, output buf.Writer) {
	writer := NewResponseWriter(s.ID, output, s.transferType)
	var err error
	if s.idleTimeout > 0 {
		err = copyPacketWithIdleClose(ctx, s, writer)
	} else {
		err = buf.Copy(s.input, writer)
	}
	if err != nil {
		recordMuxSessionEnd(err)
		errors.LogInfoInner(ctx, err, "session ", s.ID, " ends.")
		writer.hasError = true
	}

	writer.Close()
	s.Close(false)
}

const (
	packetControlIdleCloseTimeout = 10 * time.Second
)

func packetSessionIdleCloseTimeout(dest net.Destination) time.Duration {
	if dest.Network != net.Network_UDP {
		return 0
	}
	if dest.Port == net.Port(123) {
		return packetControlIdleCloseTimeout
	}
	return 0
}

func copyPacketWithIdleClose(ctx context.Context, s *Session, writer *Writer) error {
	if s.idleTimeout <= 0 {
		return buf.Copy(s.input, writer)
	}

	for {
		err := buf.CopyOnceTimeout(s.input, writer, s.idleTimeout)
		switch err {
		case nil:
			continue
		case buf.ErrReadTimeout:
			args := []any{
				"[kind=mux.packet_idle_close] ",
				"session_id=", s.ID, " ",
				"target=", s.target, " ",
				"xudp=", s.XUDP != nil, " ",
				"idle_timeout_seconds=", int(s.idleTimeout.Seconds()),
			}
			errors.LogDebug(ctx, args...)
			return nil
		case buf.ErrNotTimeoutReader:
			return buf.Copy(s.input, writer)
		default:
			return err
		}
	}
}

func (w *ServerWorker) monitor() {
	defer w.timer.Stop()

	for {
		checkSize := w.sessionManager.Size()
		checkCount := w.sessionManager.Count()
		select {
		case <-w.done.Wait():
			w.sessionManager.Close()
			common.Interrupt(w.link.Writer)
			common.Interrupt(w.link.Reader)
			return
		case <-w.timer.C:
			if w.sessionManager.CloseIfNoSessionAndIdle(checkSize, checkCount) {
				common.Must(w.done.Close())
			}
		}
	}
}

func (w *ServerWorker) ActiveConnections() uint32 {
	return uint32(w.sessionManager.Size())
}

func (w *ServerWorker) Closed() bool {
	return w.done.Done()
}

func (w *ServerWorker) WaitClosed() <-chan struct{} {
	return w.done.Wait()
}

func (w *ServerWorker) Close() error {
	return w.done.Close()
}

func (w *ServerWorker) handleStatusKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	ctx = session.SubContextFromMuxInbound(ctx)
	if meta.Inbound != nil && meta.Inbound.Source.IsValid() && meta.Inbound.Local.IsValid() {
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			newInbound := *inbound
			newInbound.Source = meta.Inbound.Source
			newInbound.Local = meta.Inbound.Local
			ctx = session.ContextWithInbound(ctx, &newInbound)
		}
	}
	errors.LogInfo(ctx, "received request for ", meta.Target)
	{
		msg := &log.AccessMessage{
			To:     meta.Target,
			Status: log.AccessAccepted,
			Reason: "",
		}
		if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.IsValid() {
			msg.From = inbound.Source
			msg.Email = inbound.User.Email
		}
		ctx = log.ContextWithAccessMessage(ctx, msg)
	}

	if network := session.AllowedNetworkFromContext(ctx); network != net.Network_Unknown {
		if meta.Target.Network != network {
			return errors.New("unexpected network ", meta.Target.Network) // it will break the whole Mux connection
		}
	}

	if meta.GlobalID != [8]byte{} { // MUST ignore empty Global ID
		mb, err := NewPacketReader(reader, &meta.Target).ReadMultiBuffer()
		if err != nil {
			return err
		}
		XUDPManager.Lock()
		x := XUDPManager.Map[meta.GlobalID]
		if x == nil {
			if len(XUDPManager.Map) >= maxXUDPSessions {
				if !xudpEvictExpiring() {
					XUDPManager.Unlock()
					recordXUDPMapFull()
					errors.LogWarning(ctx, "XUDP session map full (", maxXUDPSessions, "), rejecting new session")
					return errors.New("XUDP session limit reached")
				}
			}
			x = &XUDP{GlobalID: meta.GlobalID, CreatedAt: time.Now()}
			XUDPManager.Map[meta.GlobalID] = x
			XUDPManager.Unlock()
			recordXUDPNew()
		} else {
			if x.Status == Initializing { // nearly impossible
				XUDPManager.Unlock()
				recordXUDPConflict()
				errors.LogWarningInner(ctx, errors.New("conflict"), "XUDP hit ", meta.GlobalID)
				// It's not a good idea to return an err here, so just let client wait.
				// Client will receive an End frame after sending a Keep frame.
				return nil
			}
			x.Status = Initializing
			XUDPManager.Unlock()
			recordXUDPHit()
			x.Mux.Close(false) // detach from previous Mux
			b := buf.New()
			b.Write(mb[0].Bytes())
			b.UDP = mb[0].UDP
			if err = x.Mux.output.WriteMultiBuffer(mb); err != nil {
				x.Interrupt()
				mb = buf.MultiBuffer{b}
			} else {
				b.Release()
				mb = nil
			}
			errors.LogInfoInner(ctx, err, "XUDP hit ", meta.GlobalID)
		}
		if mb != nil {
			ctx = session.ContextWithTimeoutOnly(ctx, true)
			// Actually, it won't return an error in Xray-core's implementations.
			link, err := w.dispatcher.Dispatch(ctx, meta.Target)
			if err != nil {
				XUDPManager.Lock()
				delete(XUDPManager.Map, x.GlobalID)
				XUDPManager.Unlock()
				recordXUDPDispatchFail()
				err = errors.New("XUDP new ", meta.GlobalID).Base(errors.New("failed to dispatch request to ", meta.Target).Base(err))
				return err // it will break the whole Mux connection
			}
			link.Writer.WriteMultiBuffer(mb) // it's meaningless to test a new pipe
			x.Mux = &Session{
				input:  link.Reader,
				output: link.Writer,
			}
			errors.LogInfoInner(ctx, err, "XUDP new ", meta.GlobalID)
		}
		x.Mux = &Session{
			input:        x.Mux.input,
			output:       x.Mux.output,
			parent:       w.sessionManager,
			ID:           meta.SessionID,
			target:       meta.Target,
			transferType: protocol.TransferTypePacket,
			idleTimeout:  packetSessionIdleCloseTimeout(meta.Target),
			XUDP:         x,
		}
		x.Status = Active
		if !w.sessionManager.Add(x.Mux) {
			x.Mux.Close(false)
			return errors.New("failed to add new session")
		}
		w.sessionsCreated++
		go handle(ctx, x.Mux, w.link.Writer)
		return nil
	}

	link, err := w.dispatcher.Dispatch(ctx, meta.Target)
	if err != nil {
		if meta.Option.Has(OptionData) {
			buf.Copy(NewStreamReader(reader), buf.Discard)
		}
		return errors.New("failed to dispatch request.").Base(err)
	}
	s := &Session{
		input:        link.Reader,
		output:       link.Writer,
		parent:       w.sessionManager,
		ID:           meta.SessionID,
		target:       meta.Target,
		transferType: protocol.TransferTypeStream,
	}
	if meta.Target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
		s.idleTimeout = packetSessionIdleCloseTimeout(meta.Target)
	}
	if !w.sessionManager.Add(s) {
		s.Close(false)
		return errors.New("failed to add new session")
	}
	w.sessionsCreated++
	go handle(ctx, s, w.link.Writer)
	if !meta.Option.Has(OptionData) {
		return nil
	}

	rr := s.NewReader(reader, &meta.Target)
	err = buf.Copy(rr, s.output)

	if err != nil && buf.IsWriteError(err) {
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}
	return err
}

func (w *ServerWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, found := w.sessionManager.Get(meta.SessionID)
	if !found {
		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, w.link.Writer, protocol.TransferTypeStream)
		closingWriter.Close()

		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}

	rr := s.NewReader(reader, &meta.Target)
	err := buf.Copy(rr, s.output)

	if err != nil && buf.IsWriteError(err) {
		errors.LogInfoInner(context.Background(), err, "failed to write to downstream writer. closing session ", s.ID)
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}

	return err
}

func (w *ServerWorker) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if s, found := w.sessionManager.Get(meta.SessionID); found {
		s.Close(false)
	}
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleFrame(ctx context.Context, reader *buf.BufferedReader) error {
	var meta FrameMetadata
	err := meta.Unmarshal(reader, session.IsReverseMuxFromContext(ctx))
	if err != nil {
		return errors.New("failed to read metadata").Base(err)
	}

	switch meta.SessionStatus {
	case SessionStatusKeepAlive:
		err = w.handleStatusKeepAlive(&meta, reader)
	case SessionStatusEnd:
		err = w.handleStatusEnd(&meta, reader)
	case SessionStatusNew:
		err = w.handleStatusNew(session.ContextWithIsReverseMux(ctx, false), &meta, reader)
	case SessionStatusKeep:
		err = w.handleStatusKeep(&meta, reader)
	default:
		status := meta.SessionStatus
		return errors.New("unknown status: ", status).AtError()
	}

	if err != nil {
		return errors.New("failed to process data").Base(err)
	}
	return nil
}

func classifyMuxParentDeath(err error) string {
	cause := errors.Cause(err)
	switch {
	case cause == io.EOF:
		return "eof"
	case stderrors.Is(cause, io.ErrClosedPipe), stderrors.Is(cause, syscall.EPIPE):
		return "closed_pipe"
	case stderrors.Is(cause, syscall.ECONNRESET):
		return "connection_reset"
	default:
		return "other"
	}
}

func muxParentDeathDurations(now, createdAt, lastActivity time.Time) (idleSeconds, lifetimeSeconds int) {
	if now.Before(createdAt) {
		now = createdAt
	}
	if lastActivity.Before(createdAt) {
		lastActivity = createdAt
	}
	if now.Before(lastActivity) {
		lastActivity = now
	}
	return int(now.Sub(lastActivity).Seconds()), int(now.Sub(createdAt).Seconds())
}

func muxFirstFrameLatencyNs(createdAt, firstFrameAt time.Time) int64 {
	if firstFrameAt.IsZero() || firstFrameAt.Before(createdAt) {
		return 0
	}
	return firstFrameAt.Sub(createdAt).Nanoseconds()
}

type muxParentLifecycle struct {
	idleSeconds          int
	lifetimeSeconds      int
	activeSeconds        int
	totalFrames          int64
	totalSessionsCreated int64
	firstFrameLatencyNs  int64
}

func (w *ServerWorker) parentLifecycle(now time.Time) muxParentLifecycle {
	idleSeconds, lifetimeSeconds := muxParentDeathDurations(now, w.createdAt, w.lastActivity)
	activeSeconds := lifetimeSeconds - idleSeconds
	if activeSeconds < 0 {
		activeSeconds = 0
	}
	return muxParentLifecycle{
		idleSeconds:          idleSeconds,
		lifetimeSeconds:      lifetimeSeconds,
		activeSeconds:        activeSeconds,
		totalFrames:          w.frameCount,
		totalSessionsCreated: w.sessionsCreated,
		firstFrameLatencyNs:  muxFirstFrameLatencyNs(w.createdAt, w.firstFrameAt),
	}
}

func (w *ServerWorker) logParentBirth(ctx context.Context, concurrentParents int64) {
	errors.LogDebug(ctx,
		"[kind=mux.parent_birth] ",
		"concurrent_parents=", concurrentParents,
	)
}

func (w *ServerWorker) logParentDeath(ctx context.Context, errClass string) {
	lifecycle := w.parentLifecycle(time.Now())
	errors.LogDebug(ctx,
		"[kind=mux.parent_lifecycle] ",
		"error_class=", errClass, " ",
		"idle_seconds=", lifecycle.idleSeconds, " ",
		"lifetime_seconds=", lifecycle.lifetimeSeconds, " ",
		"active_seconds=", lifecycle.activeSeconds, " ",
		"active_sessions=", w.sessionManager.Size(), " ",
		"total_frames=", lifecycle.totalFrames, " ",
		"total_sessions_created=", lifecycle.totalSessionsCreated, " ",
		"first_frame_ns=", lifecycle.firstFrameLatencyNs, " ",
		"concurrent_parents=", atomic.LoadInt64(&activeMuxParents),
	)
}

func (w *ServerWorker) run(ctx context.Context) {
	concurrentParents := atomic.AddInt64(&activeMuxParents, 1)
	defer func() {
		atomic.AddInt64(&activeMuxParents, -1)
		common.Must(w.done.Close())
	}()
	w.logParentBirth(ctx, concurrentParents)

	reader := &buf.BufferedReader{Reader: w.link.Reader}

	for {
		select {
		case <-ctx.Done():
			w.logParentDeath(ctx, "context_cancelled")
			return
		default:
			err := w.handleFrame(ctx, reader)
			if err != nil {
				w.logParentDeath(ctx, classifyMuxParentDeath(err))
				if cause := errors.Cause(err); cause != io.EOF {
					errors.LogInfoInner(ctx, err, "unexpected EOF")
					errors.LogDebug(ctx,
						"[kind=mux.parent_stream_error_origin] ",
						"cause_type=", fmt.Sprintf("%T", cause), " ",
						"cause_msg=", cause.Error(),
					)
				}
				return
			}
			w.lastActivity = time.Now()
			w.frameCount++
			if w.firstFrameAt.IsZero() {
				w.firstFrameAt = w.lastActivity
			}
		}
	}
}
