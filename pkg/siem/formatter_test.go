package siem

import (
	"strings"
	"testing"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

func TestEscapeCEF(t *testing.T) {
	headerInput := "Pipe|Pipe\\Backslash"
	expectedHeader := "Pipe\\|Pipe\\\\Backslash"
	if got := EscapeCEFHeader(headerInput); got != expectedHeader {
		t.Errorf("EscapeCEFHeader failed: expected %q, got %q", expectedHeader, got)
	}

	extInput := "key=value\\with=equals\nnewline"
	expectedExt := "key\\=value\\\\with\\=equals\\nnewline"
	if got := EscapeCEFExtension(extInput); got != expectedExt {
		t.Errorf("EscapeCEFExtension failed: expected %q, got %q", expectedExt, got)
	}
}

func TestFormatCEF(t *testing.T) {
	alert := cbridge.Alert{
		Severity:   "CRITICAL",
		AlertType:  "BLACKLISTED_IP",
		Message:    "Traffic detected from known malicious IP: 198.51.100.23",
		Details:    "Packet size 128 bytes",
		Timestamp:  time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		SrcIP:      "198.51.100.23",
		DstIP:      "192.168.1.50",
		SrcPort:    4444,
		DstPort:    80,
		Protocol:   "TCP",
		SrcCountry: "US",
		DstCountry: "LAN",
	}

	cef := FormatCEF(alert, true)

	// Verify Header
	if !strings.HasPrefix(cef, "CEF:0|CoreMonitor|CoreMonitor|1.0|BLACKLISTED_IP|Traffic detected from known malicious IP: 198.51.100.23|10|") {
		t.Errorf("CEF header mismatch: got %q", cef)
	}

	// Verify Extensions
	if !strings.Contains(cef, "src=198.51.100.23") {
		t.Errorf("missing src in CEF: %q", cef)
	}
	if !strings.Contains(cef, "dst=192.168.1.50") {
		t.Errorf("missing dst in CEF: %q", cef)
	}
	if !strings.Contains(cef, "spt=4444") {
		t.Errorf("missing spt in CEF: %q", cef)
	}
	if !strings.Contains(cef, "dpt=80") {
		t.Errorf("missing dpt in CEF: %q", cef)
	}
	if !strings.Contains(cef, "proto=TCP") {
		t.Errorf("missing proto in CEF: %q", cef)
	}
	if !strings.Contains(cef, "act=blocked") {
		t.Errorf("expected act=blocked for jailed alert in CEF: %q", cef)
	}
	if !strings.Contains(cef, "cat=Threat Intelligence/Malicious IP") {
		t.Errorf("missing category in CEF: %q", cef)
	}
	if !strings.Contains(cef, "rt=1793534400000") {
		t.Errorf("missing timestamp in CEF: %q", cef)
	}
}

func TestFormatSyslogCEF(t *testing.T) {
	alert := cbridge.Alert{
		Severity:  "HIGH",
		AlertType: "PORT_SCAN_SYN",
		Message:   "Port scan detected",
		Timestamp: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		SrcIP:     "192.168.1.200",
		DstIP:     "192.168.1.50",
		Protocol:  "TCP",
	}

	// Facility 16 (local0) * 8 + Severity 3 (Error) = 131
	syslog := FormatSyslogCEF(alert, "sensor-01", 1234, 16, false)

	if !strings.HasPrefix(syslog, "<131>Nov  1 12:00:00 sensor-01 CoreMonitor[1234]: CEF:0|") {
		t.Errorf("unexpected RFC 3164 syslog CEF output: %q", syslog)
	}
	if !strings.Contains(syslog, "act=alert") {
		t.Errorf("expected act=alert for unjailed alert: %q", syslog)
	}
}

func TestFormatRFC5424(t *testing.T) {
	alert := cbridge.Alert{
		Severity:  "MEDIUM",
		AlertType: "SUSPICIOUS_PORT",
		Message:   "Telnet port probe",
		Timestamp: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		SrcIP:     "192.168.1.120",
		DstIP:     "192.168.1.1",
		Protocol:  "TCP",
	}

	// Facility 16 * 8 + Severity 4 (Warning) = 132
	syslog := FormatRFC5424(alert, "sensor-01", 1234, 16, false)

	if !strings.HasPrefix(syslog, "<132>1 2026-11-01T12:00:00Z sensor-01 CoreMonitor 1234 SUSPICIOUS_PORT - CEF:0|") {
		t.Errorf("unexpected RFC 5424 syslog output: %q", syslog)
	}
}
