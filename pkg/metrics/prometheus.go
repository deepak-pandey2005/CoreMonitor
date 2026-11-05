package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/engine"
)

// Config defines Prometheus HTTP server configuration.
type Config struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Endpoint   string `yaml:"endpoint"`
}

// DefaultConfig provides default Prometheus exporter options.
func DefaultConfig() Config {
	return Config{
		Enabled:    true,
		ListenAddr: "0.0.0.0:2112",
		Endpoint:   "/metrics",
	}
}

// Server hosts the Prometheus HTTP scrape endpoint.
type Server struct {
	cfg        Config
	engine     *engine.Engine
	httpServer *http.Server
	listener   net.Listener
	mu         sync.Mutex
	running    bool
}

// NewServer creates a Prometheus metrics server for CoreMonitor.
func NewServer(cfg Config, eng *engine.Engine) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:2112"
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "/metrics"
	}

	s := &Server{
		cfg:    cfg,
		engine: eng,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Endpoint, s.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return s
}

// Start spawns the HTTP server in a background goroutine.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}

	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("prometheus server failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = ln
	s.running = true
	s.mu.Unlock()

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			// server closed or errored
		}
	}()

	return nil
}

// Stop gracefully terminates the metrics server.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}
	s.running = false

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

// Addr returns the bound address (helpful if port 0 was assigned in tests).
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.cfg.ListenAddr
}

// handleMetrics serializes engine stats into standard Prometheus text exposition format (version 0.0.4).
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		http.Error(w, "Engine not ready", http.StatusServiceUnavailable)
		return
	}

	stats := s.engine.GetStats()
	var b strings.Builder

	// Header comments
	b.WriteString("# CoreMonitor Network Traffic & Security IDS/IPS Prometheus Metrics\n")

	// Total Packets
	b.WriteString("# HELP coremonitor_packets_total Total number of packets processed\n")
	b.WriteString("# TYPE coremonitor_packets_total counter\n")
	b.WriteString(fmt.Sprintf("coremonitor_packets_total %d\n\n", stats.TotalPackets))

	// Total Bytes
	b.WriteString("# HELP coremonitor_bytes_total Total volume of network traffic processed in bytes\n")
	b.WriteString("# TYPE coremonitor_bytes_total counter\n")
	b.WriteString(fmt.Sprintf("coremonitor_bytes_total %d\n\n", stats.TotalBytes))

	// Rates
	b.WriteString("# HELP coremonitor_packets_per_second Current instantaneous packet processing rate\n")
	b.WriteString("# TYPE coremonitor_packets_per_second gauge\n")
	b.WriteString(fmt.Sprintf("coremonitor_packets_per_second %.2f\n\n", stats.PktsPerSec))

	b.WriteString("# HELP coremonitor_bytes_per_second Current instantaneous bandwidth throughput in bytes/second\n")
	b.WriteString("# TYPE coremonitor_bytes_per_second gauge\n")
	b.WriteString(fmt.Sprintf("coremonitor_bytes_per_second %.2f\n\n", stats.BytesPerSec))

	// Protocol Counts
	if len(stats.ProtocolCounts) > 0 {
		b.WriteString("# HELP coremonitor_protocol_packets_total Total packets broken down by protocol\n")
		b.WriteString("# TYPE coremonitor_protocol_packets_total counter\n")
		for proto, count := range stats.ProtocolCounts {
			b.WriteString(fmt.Sprintf("coremonitor_protocol_packets_total{protocol=%q} %d\n", proto, count))
		}
		b.WriteString("\n")
	}

	// Security Alerts
	b.WriteString("# HELP coremonitor_alerts_total Total security intrusion alerts detected\n")
	b.WriteString("# TYPE coremonitor_alerts_total counter\n")
	if len(stats.CumulativeAlerts) == 0 {
		b.WriteString(fmt.Sprintf("coremonitor_alerts_total %d\n", stats.TotalAlerts))
	} else {
		for sev, types := range stats.CumulativeAlerts {
			for aType, count := range types {
				b.WriteString(fmt.Sprintf("coremonitor_alerts_total{severity=%q,alert_type=%q} %d\n", sev, aType, count))
			}
		}
	}
	b.WriteString("\n")

	// Active Defense (IPS) Jails
	b.WriteString("# HELP coremonitor_ips_banned_hosts Total active jailed/blocked attacker hosts\n")
	b.WriteString("# TYPE coremonitor_ips_banned_hosts gauge\n")
	b.WriteString(fmt.Sprintf("coremonitor_ips_banned_hosts %d\n\n", len(stats.BannedHosts)))

	// 5-Tuple Flows
	b.WriteString("# HELP coremonitor_active_flows Current active 5-tuple conversation flows\n")
	b.WriteString("# TYPE coremonitor_active_flows gauge\n")
	b.WriteString(fmt.Sprintf("coremonitor_active_flows %d\n\n", stats.FlowStats.ActiveFlows))

	b.WriteString("# HELP coremonitor_flows_total Total conversation flows created over lifetime\n")
	b.WriteString("# TYPE coremonitor_flows_total counter\n")
	b.WriteString(fmt.Sprintf("coremonitor_flows_total %d\n\n", stats.FlowStats.TotalFlowsCreated))

	// SIEM Exporter Metrics
	b.WriteString("# HELP coremonitor_siem_events_total Total SIEM CEF and Syslog events processed\n")
	b.WriteString("# TYPE coremonitor_siem_events_total counter\n")
	b.WriteString(fmt.Sprintf("coremonitor_siem_events_total{status=\"sent\"} %d\n", stats.SIEMStats.EventsSent))
	b.WriteString(fmt.Sprintf("coremonitor_siem_events_total{status=\"dropped\"} %d\n", stats.SIEMStats.EventsDropped))
	b.WriteString(fmt.Sprintf("coremonitor_siem_events_total{status=\"error\"} %d\n", stats.SIEMStats.SendErrors))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

