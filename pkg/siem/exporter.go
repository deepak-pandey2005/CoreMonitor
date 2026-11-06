package siem

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

// ExporterStats tracks performance and operational telemetry of the SIEM exporter.
type ExporterStats struct {
	EventsSent    uint64
	EventsDropped uint64
	SendErrors    uint64
}

// Exporter manages asynchronous non-blocking event streaming to SIEM collectors.
type Exporter struct {
	cfg      Config
	queue    chan string
	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	eventsSent    uint64
	eventsDropped uint64
	sendErrors    uint64
}

// NewExporter initializes a new background SIEM streaming exporter.
func NewExporter(cfg Config) *Exporter {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	if cfg.Format == "" {
		cfg.Format = "cef"
	}
	if cfg.Transport == "" {
		cfg.Transport = "udp"
	}
	if cfg.Address == "" {
		cfg.Address = "127.0.0.1:514"
	}
	if cfg.Facility <= 0 {
		cfg.Facility = 16
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = "LOW"
	}

	exp := &Exporter{
		cfg:      cfg,
		queue:    make(chan string, cfg.QueueSize),
		stopChan: make(chan struct{}),
	}

	if cfg.Enabled {
		exp.wg.Add(1)
		go exp.runWorker()
	}

	return exp
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// SendAlert formats and queues an IDS security alert for SIEM transmission.
// Returns false if dropped, filtered, or exporter is disabled.
func (e *Exporter) SendAlert(alert cbridge.Alert, jailed bool) bool {
	if !e.cfg.Enabled {
		return false
	}

	if severityRank(alert.Severity) < severityRank(e.cfg.MinSeverity) {
		return false
	}

	var formatted string
	switch strings.ToLower(e.cfg.Format) {
	case "syslog-cef", "rfc3164":
		formatted = FormatSyslogCEF(alert, "", 0, e.cfg.Facility, jailed)
	case "rfc5424":
		formatted = FormatRFC5424(alert, "", 0, e.cfg.Facility, jailed)
	case "cef":
		fallthrough
	default:
		formatted = FormatCEF(alert, jailed)
	}

	return e.enqueue(formatted)
}

// SendRaw queues a pre-formatted log message.
func (e *Exporter) SendRaw(msg string) bool {
	if !e.cfg.Enabled {
		return false
	}
	return e.enqueue(msg)
}

func (e *Exporter) enqueue(msg string) bool {
	select {
	case <-e.stopChan:
		atomic.AddUint64(&e.eventsDropped, 1)
		return false
	case e.queue <- msg:
		return true
	default:
		atomic.AddUint64(&e.eventsDropped, 1)
		return false
	}
}

// GetStats returns snapshot counters of SIEM transmissions.
func (e *Exporter) GetStats() ExporterStats {
	return ExporterStats{
		EventsSent:    atomic.LoadUint64(&e.eventsSent),
		EventsDropped: atomic.LoadUint64(&e.eventsDropped),
		SendErrors:    atomic.LoadUint64(&e.sendErrors),
	}
}

// Close gracefully terminates the SIEM exporter and flushes remaining queue items.
func (e *Exporter) Close() {
	e.stopOnce.Do(func() {
		close(e.stopChan)
		e.wg.Wait()
	})
}

func (e *Exporter) runWorker() {
	defer e.wg.Done()

	transport := strings.ToLower(e.cfg.Transport)
	switch transport {
	case "file":
		e.runFileWorker()
	case "tcp":
		e.runTCPWorker()
	case "udp":
		fallthrough
	default:
		e.runUDPWorker()
	}
}

func (e *Exporter) runFileWorker() {
	filePath := e.cfg.FilePath
	if filePath == "" {
		filePath = "captures/siem_events.log"
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		atomic.AddUint64(&e.sendErrors, 1)
		return
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		atomic.AddUint64(&e.sendErrors, 1)
		return
	}
	defer file.Close()

	for {
		select {
		case msg := <-e.queue:
			if _, err := fmt.Fprintln(file, msg); err != nil {
				atomic.AddUint64(&e.sendErrors, 1)
			} else {
				atomic.AddUint64(&e.eventsSent, 1)
			}
		case <-e.stopChan:
			// Drain queue before quitting
			for {
				select {
				case msg := <-e.queue:
					if _, err := fmt.Fprintln(file, msg); err != nil {
						atomic.AddUint64(&e.sendErrors, 1)
					} else {
						atomic.AddUint64(&e.eventsSent, 1)
					}
				default:
					return
				}
			}
		}
	}
}

func (e *Exporter) runUDPWorker() {
	conn, err := net.Dial("udp", e.cfg.Address)
	if err != nil {
		atomic.AddUint64(&e.sendErrors, 1)
	}
	if conn != nil {
		defer conn.Close()
	}

	for {
		select {
		case msg := <-e.queue:
			if conn == nil {
				conn, err = net.Dial("udp", e.cfg.Address)
				if err != nil {
					atomic.AddUint64(&e.sendErrors, 1)
					continue
				}
			}
			data := []byte(msg + "\n")
			if _, err := conn.Write(data); err != nil {
				atomic.AddUint64(&e.sendErrors, 1)
			} else {
				atomic.AddUint64(&e.eventsSent, 1)
			}
		case <-e.stopChan:
			// Drain remaining
			for {
				select {
				case msg := <-e.queue:
					if conn != nil {
						_, _ = conn.Write([]byte(msg + "\n"))
						atomic.AddUint64(&e.eventsSent, 1)
					}
				default:
					return
				}
			}
		}
	}
}

func (e *Exporter) runTCPWorker() {
	var conn net.Conn
	var lastConnectAttempt time.Time
	reconnectBackoff := 2 * time.Second

	connect := func() net.Conn {
		lastConnectAttempt = time.Now()
		c, err := net.DialTimeout("tcp", e.cfg.Address, 2*time.Second)
		if err != nil {
			atomic.AddUint64(&e.sendErrors, 1)
			return nil
		}
		return c
	}

	conn = connect()
	if conn != nil {
		defer conn.Close()
	}

	for {
		select {
		case msg := <-e.queue:
			if conn == nil {
				if time.Since(lastConnectAttempt) < reconnectBackoff {
					atomic.AddUint64(&e.sendErrors, 1)
					continue
				}
				conn = connect()
				if conn == nil {
					continue
				}
			}

			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			data := []byte(msg + "\n")
			if _, err := conn.Write(data); err != nil {
				atomic.AddUint64(&e.sendErrors, 1)
				_ = conn.Close()
				conn = nil
			} else {
				atomic.AddUint64(&e.eventsSent, 1)
			}
		case <-e.stopChan:
			// Drain remaining
			for {
				select {
				case msg := <-e.queue:
					if conn != nil {
						_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
						_, _ = conn.Write([]byte(msg + "\n"))
						atomic.AddUint64(&e.eventsSent, 1)
					}
				default:
					return
				}
			}
		}
	}
}

