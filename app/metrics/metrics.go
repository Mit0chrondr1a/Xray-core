package metrics

import (
	"context"
	"expvar"
	"net/http"
	"net/http/pprof"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	feature_stats "github.com/xtls/xray-core/features/stats"
)

type MetricsHandler struct {
	ohm            outbound.Manager
	statsManager   feature_stats.Manager
	observatory    extension.Observatory
	tag            string
	listen         string
	tcpListener    net.Listener
	tcpServer      *http.Server
	outboundServer *http.Server
	mux            *http.ServeMux
}

// NewMetricsHandler creates a new MetricsHandler based on the given config.
func NewMetricsHandler(ctx context.Context, config *Config) (*MetricsHandler, error) {
	mux := http.NewServeMux()

	c := &MetricsHandler{
		tag:    config.Tag,
		listen: config.Listen,
		mux:    mux,
	}
	common.Must(core.RequireFeatures(ctx, func(om outbound.Manager, sm feature_stats.Manager) {
		c.statsManager = sm
		c.ohm = om
	}))

	expvar.Publish("stats", expvar.Func(func() interface{} {
		manager, ok := c.statsManager.(*stats.Manager)
		if !ok {
			return nil
		}
		resp := map[string]map[string]map[string]int64{
			"inbound":  {},
			"outbound": {},
			"user":     {},
		}
		manager.VisitCounters(func(name string, counter feature_stats.Counter) bool {
			nameSplit := strings.Split(name, ">>>")
			if len(nameSplit) < 4 {
				errors.LogWarning(context.Background(), "invalid stats counter name: ", name)
				return true
			}
			typeName, tagOrUser, direction := nameSplit[0], nameSplit[1], nameSplit[3]
			if item, found := resp[typeName][tagOrUser]; found {
				item[direction] = counter.Value()
			} else {
				resp[typeName][tagOrUser] = map[string]int64{
					direction: counter.Value(),
				}
			}
			return true
		})
		return resp
	}))
	expvar.Publish("observatory", expvar.Func(func() interface{} {
		if c.observatory == nil {
			common.Must(core.RequireFeatures(ctx, func(observatory extension.Observatory) error {
				c.observatory = observatory
				return nil
			}))
			if c.observatory == nil {
				return nil
			}
		}
		resp := map[string]*observatory.OutboundStatus{}
		if o, err := c.observatory.GetObservation(context.Background()); err != nil {
			return err
		} else {
			for _, x := range o.(*observatory.ObservationResult).GetStatus() {
				resp[x.OutboundTag] = x
			}
		}
		return resp
	}))

	// Register pprof handlers on dedicated mux
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// Register expvar handler on dedicated mux
	mux.Handle("/debug/vars", expvar.Handler())

	// Health check endpoint for container orchestration (Kubernetes, Docker)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	return c, nil
}

func (p *MetricsHandler) Type() interface{} {
	return (*MetricsHandler)(nil)
}

func (p *MetricsHandler) Start() error {

	// direct listen a port if listen is set
	if p.listen != "" {
		TCPlistener, err := net.Listen("tcp", p.listen)
		if err != nil {
			return err
		}
		p.tcpListener = TCPlistener
		p.tcpServer = &http.Server{
			Handler:           p.mux,
			ReadHeaderTimeout: 4 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		errors.LogInfo(context.Background(), "Metrics server listening on ", p.listen)

		go func() {
			if err := p.tcpServer.Serve(TCPlistener); err != nil && err != http.ErrServerClosed {
				errors.LogErrorInner(context.Background(), err, "failed to start metrics server")
			}
		}()
	}

	listener := &OutboundListener{
		buffer: make(chan net.Conn, 4),
		done:   done.New(),
	}

	p.outboundServer = &http.Server{
		Handler:           p.mux,
		ReadHeaderTimeout: 4 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go func() {
		if err := p.outboundServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			errors.LogErrorInner(context.Background(), err, "failed to start metrics server")
		}
	}()

	if err := p.ohm.RemoveHandler(context.Background(), p.tag); err != nil {
		errors.LogInfo(context.Background(), "failed to remove existing handler")
	}

	return p.ohm.AddHandler(context.Background(), &Outbound{
		tag:      p.tag,
		listener: listener,
	})
}

func (p *MetricsHandler) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var firstErr error
	if p.tcpServer != nil {
		if err := p.tcpServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if p.outboundServer != nil {
		if err := p.outboundServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewMetricsHandler(ctx, cfg.(*Config))
	}))
}
