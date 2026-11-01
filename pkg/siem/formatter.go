package siem

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

// EscapeCEFHeader escapes backslashes and vertical bars in CEF header fields.
func EscapeCEFHeader(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

// EscapeCEFExtension escapes backslashes, equals signs, and newlines in CEF extension values.
func EscapeCEFExtension(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

// MapSeverityToCEF converts human severity levels to ArcSight CEF integer range (0-10).
func MapSeverityToCEF(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 10
	case "HIGH":
		return 7
	case "MEDIUM":
		return 5
	case "LOW":
		return 3
	default:
		return 1
	}
}

// MapSeverityToSyslog converts severity to RFC 5424 / RFC 3164 syslog severity level.
// 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Informational, 7=Debug.
func MapSeverityToSyslog(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 1 // Alert
	case "HIGH":
		return 3 // Error
	case "MEDIUM":
		return 4 // Warning
	case "LOW":
		return 5 // Notice
	default:
		return 6 // Informational
	}
}

// CategorizeThreat determines the standard SIEM category based on alert signature.
func CategorizeThreat(alertType string) string {
	switch alertType {
	case "PORT_SCAN_SYN":
		return "Reconnaissance/PortScan"
	case "XMAS_SCAN", "NULL_SCAN", "FIN_SCAN":
		return "Reconnaissance/StealthScan"
	case "SYN_FLOOD", "ICMP_FLOOD", "BANDWIDTH_SPIKE":
		return "Denial of Service/Flood"
	case "DNS_TUNNEL_ANOMALY":
		return "Malware/Exfiltration"
	case "BLACKLISTED_IP":
		return "Threat Intelligence/Malicious IP"
	case "ARP_SPOOFING", "GRATUITOUS_ARP":
		return "Man-In-The-Middle/ARP"
	case "SUSPICIOUS_PORT":
		return "Policy Violation/Suspicious Port"
	default:
		return "Network/Intrusion"
	}
}

// FormatCEF generates a standard ArcSight Common Event Format (CEF:0) record.
func FormatCEF(alert cbridge.Alert, jailed bool) string {
	cefSev := MapSeverityToCEF(alert.Severity)
	vendor := "CoreMonitor"
	product := "CoreMonitor"
	version := "1.0"
	eventClassID := EscapeCEFHeader(alert.AlertType)
	eventName := EscapeCEFHeader(alert.Message)

	// Build standard CEF extension key-value pairs
	var ext []string
	if alert.SrcIP != "" && alert.SrcIP != "unknown" {
		ext = append(ext, fmt.Sprintf("src=%s", EscapeCEFExtension(alert.SrcIP)))
	}
	if alert.DstIP != "" && alert.DstIP != "unknown" {
		ext = append(ext, fmt.Sprintf("dst=%s", EscapeCEFExtension(alert.DstIP)))
	}
	if alert.SrcPort > 0 {
		ext = append(ext, fmt.Sprintf("spt=%d", alert.SrcPort))
	}
	if alert.DstPort > 0 {
		ext = append(ext, fmt.Sprintf("dpt=%d", alert.DstPort))
	}
	if alert.Protocol != "" {
		ext = append(ext, fmt.Sprintf("proto=%s", EscapeCEFExtension(alert.Protocol)))
	}
	if alert.SrcCountry != "" {
		ext = append(ext, fmt.Sprintf("shost=%s", EscapeCEFExtension(alert.SrcCountry)))
	}
	if alert.DstCountry != "" {
		ext = append(ext, fmt.Sprintf("dhost=%s", EscapeCEFExtension(alert.DstCountry)))
	}

	act := "alert"
	if jailed {
		act = "blocked"
	}
	ext = append(ext, fmt.Sprintf("act=%s", act))

	cat := CategorizeThreat(alert.AlertType)
	ext = append(ext, fmt.Sprintf("cat=%s", EscapeCEFExtension(cat)))

	if alert.Details != "" {
		ext = append(ext, fmt.Sprintf("msg=%s", EscapeCEFExtension(alert.Details)))
	}

	tsMillis := alert.Timestamp.UnixMilli()
	if tsMillis <= 0 {
		tsMillis = time.Now().UnixMilli()
	}
	ext = append(ext, fmt.Sprintf("rt=%d", tsMillis))

	extensionsStr := strings.Join(ext, " ")

	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		vendor, product, version, eventClassID, eventName, cefSev, extensionsStr)
}

// FormatSyslogCEF wraps a CEF message in standard RFC 3164 Syslog envelope (widely used by Splunk/Wazuh).
func FormatSyslogCEF(alert cbridge.Alert, hostname string, pid int, facility int, jailed bool) string {
	if hostname == "" {
		hostname, _ = os.Hostname()
		if hostname == "" {
			hostname = "coremonitor"
		}
	}
	if pid <= 0 {
		pid = os.Getpid()
	}
	if facility <= 0 {
		facility = 16 // local0
	}

	syslogSev := MapSeverityToSyslog(alert.Severity)
	pri := (facility * 8) + syslogSev

	ts := alert.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	timeStr := ts.Format("Jan _2 15:04:05")

	cefBody := FormatCEF(alert, jailed)
	return fmt.Sprintf("<%d>%s %s CoreMonitor[%d]: %s", pri, timeStr, hostname, pid, cefBody)
}

// FormatRFC5424 wraps a CEF message in modern RFC 5424 Syslog envelope.
func FormatRFC5424(alert cbridge.Alert, hostname string, pid int, facility int, jailed bool) string {
	if hostname == "" {
		hostname, _ = os.Hostname()
		if hostname == "" {
			hostname = "coremonitor"
		}
	}
	if pid <= 0 {
		pid = os.Getpid()
	}
	if facility <= 0 {
		facility = 16
	}

	syslogSev := MapSeverityToSyslog(alert.Severity)
	pri := (facility * 8) + syslogSev

	ts := alert.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	timeStr := ts.Format(time.RFC3339Nano)

	cefBody := FormatCEF(alert, jailed)
	return fmt.Sprintf("<%d>1 %s %s CoreMonitor %d %s - %s",
		pri, timeStr, hostname, pid, alert.AlertType, cefBody)
}
