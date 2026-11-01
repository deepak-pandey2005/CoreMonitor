package siem

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

func TestSIEMExporterUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock UDP listener: %v", err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().String()

	cfg := Config{
		Enabled:     true,
		Format:      "cef",
		Transport:   "udp",
		Address:     addr,
		MinSeverity: "LOW",
		QueueSize:   100,
	}

	exp := NewExporter(cfg)
	defer exp.Close()

	alert := cbridge.Alert{
		Severity:  "CRITICAL",
		AlertType: "SYN_FLOOD",
		Message:   "SYN flood attack detected",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.1",
		Protocol:  "TCP",
	}

	if !exp.SendAlert(alert, true) {
		t.Errorf("expected SendAlert to succeed")
	}

	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed reading from mock UDP listener: %v", err)
	}

	received := string(buf[:n])
	if !strings.HasPrefix(received, "CEF:0|CoreMonitor|CoreMonitor|1.0|SYN_FLOOD|SYN flood attack detected|10|") {
		t.Errorf("unexpected UDP CEF message: %q", received)
	}
	if !strings.Contains(received, "act=blocked") {
		t.Errorf("expected act=blocked in UDP message: %q", received)
	}

	stats := exp.GetStats()
	if stats.EventsSent == 0 {
		t.Errorf("expected EventsSent > 0, got %d", stats.EventsSent)
	}
}

func TestSIEMExporterTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock TCP listener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	receivedChan := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		scanner := bufio.NewScanner(conn)
		if scanner.Scan() {
			receivedChan <- scanner.Text()
		}
	}()

	cfg := Config{
		Enabled:     true,
		Format:      "syslog-cef",
		Transport:   "tcp",
		Address:     addr,
		Facility:    16,
		MinSeverity: "MEDIUM",
		QueueSize:   100,
	}

	exp := NewExporter(cfg)
	defer exp.Close()

	alert := cbridge.Alert{
		Severity:  "HIGH",
		AlertType: "XMAS_SCAN",
		Message:   "Stealth Xmas scan detected",
		Timestamp: time.Now(),
		SrcIP:     "10.0.0.50",
		DstIP:     "10.0.0.1",
		Protocol:  "TCP",
	}

	if !exp.SendAlert(alert, false) {
		t.Errorf("expected SendAlert to succeed")
	}

	select {
	case msg := <-receivedChan:
		if !strings.Contains(msg, "CoreMonitor") || !strings.Contains(msg, "CEF:0|") {
			t.Errorf("unexpected TCP message format: %q", msg)
		}
		if !strings.Contains(msg, "XMAS_SCAN") {
			t.Errorf("missing XMAS_SCAN in TCP payload: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for TCP message")
	}
}

func TestSIEMExporterFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "siem_test.log")

	cfg := Config{
		Enabled:     true,
		Format:      "rfc5424",
		Transport:   "file",
		FilePath:    logPath,
		MinSeverity: "LOW",
		QueueSize:   100,
	}

	exp := NewExporter(cfg)

	alert := cbridge.Alert{
		Severity:  "MEDIUM",
		AlertType: "DNS_TUNNEL_ANOMALY",
		Message:   "Long DNS query detected",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.105",
		DstIP:     "8.8.8.8",
		Protocol:  "UDP",
	}

	if !exp.SendAlert(alert, false) {
		t.Errorf("expected SendAlert to succeed")
	}

	// Close flushes queue to file
	exp.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "DNS_TUNNEL_ANOMALY") || !strings.Contains(content, "CEF:0|") {
		t.Errorf("file does not contain expected RFC 5424 CEF log: %q", content)
	}
}

func TestSIEMSeverityFiltering(t *testing.T) {
	cfg := Config{
		Enabled:     true,
		Format:      "cef",
		Transport:   "file",
		FilePath:    filepath.Join(t.TempDir(), "filtered.log"),
		MinSeverity: "HIGH",
	}

	exp := NewExporter(cfg)
	defer exp.Close()

	lowAlert := cbridge.Alert{
		Severity:  "LOW",
		AlertType: "SUSPICIOUS_PORT",
		Message:   "Low severity port",
	}
	if exp.SendAlert(lowAlert, false) {
		t.Errorf("expected LOW alert to be filtered when minSeverity=HIGH")
	}

	highAlert := cbridge.Alert{
		Severity:  "HIGH",
		AlertType: "PORT_SCAN_SYN",
		Message:   "High severity scan",
	}
	if !exp.SendAlert(highAlert, false) {
		t.Errorf("expected HIGH alert to be accepted when minSeverity=HIGH")
	}
}

