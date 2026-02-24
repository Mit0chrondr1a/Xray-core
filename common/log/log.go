package log // import "github.com/xtls/xray-core/common/log"

import (
	"sync"

	"github.com/xtls/xray-core/common/serial"
)

// Message is the interface for all log messages.
type Message interface {
	String() string
}

// Handler is the interface for log handler.
type Handler interface {
	Handle(msg Message)
}

// SeverityAwareHandler optionally exposes severity-level filtering state.
// Handlers that do not implement this interface are treated as accepting all
// severities.
type SeverityAwareHandler interface {
	IsSeverityEnabled(severity Severity) bool
}

// GeneralMessage is a general log message that can contain all kind of content.
type GeneralMessage struct {
	Severity Severity
	Content  interface{}
}

// String implements Message.
func (m *GeneralMessage) String() string {
	return serial.Concat("[", m.Severity, "] ", m.Content)
}

// Record writes a message into log stream.
func Record(msg Message) {
	logHandler.Handle(msg)
}

// IsSeverityEnabled reports whether the current log handler would accept
// GeneralMessage at the specified severity.
func IsSeverityEnabled(severity Severity) bool {
	logHandler.RLock()
	defer logHandler.RUnlock()

	if logHandler.Handler == nil {
		return true
	}

	if h, ok := logHandler.Handler.(SeverityAwareHandler); ok {
		return h.IsSeverityEnabled(severity)
	}

	return true
}

var logHandler syncHandler

// RegisterHandler registers a new handler as current log handler. Previous registered handler will be discarded.
func RegisterHandler(handler Handler) {
	if handler == nil {
		return // silently ignore nil handler rather than crashing the process
	}
	logHandler.Set(handler)
}

type syncHandler struct {
	sync.RWMutex
	Handler
}

func (h *syncHandler) Handle(msg Message) {
	h.RLock()
	defer h.RUnlock()

	if h.Handler != nil {
		h.Handler.Handle(msg)
	}
}

func (h *syncHandler) Set(handler Handler) {
	h.Lock()
	defer h.Unlock()

	h.Handler = handler
}
