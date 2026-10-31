package cbridge

import (
	"testing"
	"time"
)

func TestIDSEngineBridge(t *testing.T) {
	ids := NewIDSEngine(DefaultIDSConfig())
	defer ids.Close()

	meta := &PacketMeta{
		Timestamp:   time.Now().UTC(),
		SrcIP:       "198.51.100.23", // Blacklisted IP
		DstIP:       "10.0.0.1",
		Protocol:    "TCP",
		TCPFlags:    CMonitorTCPACK,
		TCPFlagsStr: "ACK",
		PacketSize:  64,
	}

	alerts := ids.Analyze(meta)
	if len(alerts) == 0 {
		t.Fatalf("expected alert for blacklisted IP, got 0")
	}

	if alerts[0].AlertType != "BLACKLISTED_IP" {
		t.Errorf("expected BLACKLISTED_IP, got %s", alerts[0].AlertType)
	}

	if alerts[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", alerts[0].Severity)
	}
}

func TestCaptureOfflineHTTPAndTLS(t *testing.T) {
	cap, err := OpenOffline("../../tests/fixtures/attack_sample.pcap", "")
	if err != nil {
		t.Fatalf("failed to open pcap: %v", err)
	}
	defer cap.Close()

	foundHTTP := false
	foundTLS := false

	for {
		meta, _, err := cap.Next()
		if err == ErrEOF {
			break
		}
		if err != nil {
			t.Fatalf("capture error: %v", err)
		}

		if meta.TLSSNI == "github.com" {
			foundTLS = true
		}
		if meta.HTTPMethod == "GET" && meta.HTTPHost == "example.com" {
			foundHTTP = true
		}
	}

	if !foundTLS {
		t.Errorf("expected to find TLS SNI 'github.com' in attack_sample.pcap")
	}
	if !foundHTTP {
		t.Errorf("expected to find HTTP request 'GET example.com' in attack_sample.pcap")
	}
}

const (
	CMonitorTCPFIN = 0x01
	CMonitorTCPSYN = 0x02
	CMonitorTCPRST = 0x04
	CMonitorTCPPSH = 0x08
	CMonitorTCPACK = 0x10
	CMonitorTCPURG = 0x20
)
