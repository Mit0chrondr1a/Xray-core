package pipe

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/policy"
)

// pipeImpl is the internal interface shared by pipe and spscPipe.
type pipeImpl interface {
	ReadMultiBuffer() (buf.MultiBuffer, error)
	ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error)
	WriteMultiBuffer(buf.MultiBuffer) error
	Close() error
	Interrupt()
	Len() int32
}

// Option for creating new Pipes.
type Option func(*pipeOption)

// WithoutSizeLimit returns an Option for Pipe to have no size limit.
func WithoutSizeLimit() Option {
	return func(opt *pipeOption) {
		opt.limit = -1
	}
}

// WithSizeLimit returns an Option for Pipe to have the given size limit.
func WithSizeLimit(limit int32) Option {
	return func(opt *pipeOption) {
		opt.limit = limit
	}
}

// DiscardOverflow returns an Option for Pipe to discard writes if full.
func DiscardOverflow() Option {
	return func(opt *pipeOption) {
		opt.discardOverflow = true
	}
}

// OptionsFromContext returns a list of Options from context.
func OptionsFromContext(ctx context.Context) []Option {
	var opt []Option

	bp := policy.BufferPolicyFromContext(ctx)
	if bp.PerConnection >= 0 {
		opt = append(opt, WithSizeLimit(bp.PerConnection))
	} else {
		opt = append(opt, WithoutSizeLimit())
	}

	return opt
}

// New creates a new Reader and Writer that connects to each other.
func New(opts ...Option) (*Reader, *Writer) {
	p := &pipe{
		readSignal:  signal.NewNotifier(),
		writeSignal: signal.NewNotifier(),
		done:        done.New(),
		errChan:     make(chan error, 1),
		option: pipeOption{
			limit: -1,
		},
	}

	for _, opt := range opts {
		opt(&(p.option))
	}

	return &Reader{
			impl:    p,
			errChan: p.errChan,
		}, &Writer{
			impl: p,
		}
}

// NewSPSC creates a new SPSC (single-producer single-consumer) pipe pair.
// This variant uses a lock-free ring buffer and is suitable for flows
// where exactly one goroutine writes and one goroutine reads.
// The capacity parameter specifies the ring buffer size in bytes
// (rounded up to the next power of 2, minimum 16 bytes).
func NewSPSC(capacity int) (*Reader, *Writer) {
	errChan := make(chan error, 1)
	p := &spscPipe{
		ring:        NewSPSCRingBuffer(capacity),
		readSignal:  signal.NewNotifier(),
		writeSignal: signal.NewNotifier(),
		done:        done.New(),
		errChan:     errChan,
	}

	return &Reader{
			impl:    p,
			errChan: errChan,
		}, &Writer{
			impl: p,
		}
}
