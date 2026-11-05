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

func TestIDSEngineConcurrentAnalyze(t *testing.T) {
	ids := NewIDSEngine(DefaultIDSConfig())
	defer ids.Close()

	const numGoroutines = 8
	const numPackets = 100
	done := make(chan bool, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			for i := 0; i < numPackets; i++ {
				meta := &PacketMeta{
					Timestamp:   time.Now().UTC(),
					SrcIP:       "192.168.1.10",
					DstIP:       "10.0.0.1",
					SrcPort:     uint16(10000 + gid),
					DstPort:     4444, // Metasploit port
					Protocol:    "TCP",
					TCPFlags:    CMonitorTCPSYN,
					TCPFlagsStr: "SYN",
					PacketSize:  64,
				}
				_ = ids.Analyze(meta)
			}
			done <- true
		}(g)
	}

	for g := 0; g < numGoroutines; g++ {
		<-done
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

func TestCaptureSetBPFFilter(t *testing.T) {
	cap, err := OpenOffline("../../tests/fixtures/attack_sample.pcap", "")
	if err != nil {
		t.Fatalf("failed to open pcap: %v", err)
	}
	defer cap.Close()

	// 1. Valid filter
	if err := cap.SetBPFFilter("tcp and port 443"); err != nil {
		t.Errorf("expected valid filter to succeed, got: %v", err)
	}

	// 2. Clear filter
	if err := cap.SetBPFFilter(""); err != nil {
		t.Errorf("expected empty filter to succeed, got: %v", err)
	}

	// 3. Invalid filter syntax
	err = cap.SetBPFFilter("invalid syntax syntax 1234")
	if err == nil {
		t.Errorf("expected error on invalid BPF syntax, got nil")
	}
}

func TestCaptureRawLengthSafety(t *testing.T) {
	cap, err := OpenOffline("../../tests/fixtures/attack_sample.pcap", "")
	if err != nil {
		t.Fatalf("failed to open pcap: %v", err)
	}
	defer cap.Close()

	packetCount := 0
	for {
		meta, raw, err := cap.Next()
		if err == ErrEOF {
			break
		}
		if err != nil {
			t.Fatalf("capture error: %v", err)
		}
		packetCount++
		// The captured raw byte slice length must never exceed the reported packet wire size
		if uint32(len(raw)) > meta.PacketSize {
			t.Errorf("raw byte length %d exceeded wire packet size %d", len(raw), meta.PacketSize)
		}
	}
	if packetCount == 0 {
		t.Errorf("expected packets from fixture, got 0")
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

func BenchmarkIDSEngineAnalyze(b *testing.B) {
	ids := NewIDSEngine(DefaultIDSConfig())
	defer ids.Close()

	meta := &PacketMeta{
		Timestamp:   time.Now().UTC(),
		SrcIP:       "192.168.1.50",
		DstIP:       "10.0.0.1",
		Protocol:    "TCP",
		Service:     "HTTP",
		SrcPort:     54321,
		DstPort:     80,
		PacketSize:  128,
		PayloadSize: 64,
		SrcMAC:      "00:11:22:33:44:55",
		DstMAC:      "66:77:88:99:aa:bb",
		DNSQuery:    "example.com",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ids.Analyze(meta)
	}
}
