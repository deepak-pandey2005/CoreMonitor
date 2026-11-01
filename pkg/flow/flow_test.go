package flow

import (
	"testing"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

func TestCanonicalKeySymmetry(t *testing.T) {
	k1, isInit1 := MakeCanonicalKey("TCP", "192.168.1.10", "93.184.216.34", 51234, 443)
	k2, isInit2 := MakeCanonicalKey("TCP", "93.184.216.34", "192.168.1.10", 443, 51234)

	if k1 != k2 {
		t.Fatalf("expected keys to be identical, got %+v and %+v", k1, k2)
	}

	if isInit1 == isInit2 {
		t.Errorf("expected isInit to be opposite for reverse endpoints")
	}
}

func TestBidirectionalFlowIngestion(t *testing.T) {
	mgr := NewManager(10*time.Second, 60*time.Second)
	defer mgr.Close()

	t0 := time.Now().UTC()
	p1 := &cbridge.PacketMeta{
		Timestamp:  t0,
		Protocol:   "TCP",
		SrcIP:      "192.168.1.50",
		DstIP:      "140.82.112.4",
		SrcPort:    45000,
		DstPort:    443,
		PacketSize: 150,
		TLSSNI:     "github.com",
		Service:    "HTTPS",
	}

	f1 := mgr.Ingest(p1)
	if f1 == nil {
		t.Fatalf("expected valid flow")
	}
	if f1.TotalPackets != 1 || f1.TotalBytes != 150 {
		t.Errorf("expected 1 pkt 150 bytes, got %d pkts %d bytes", f1.TotalPackets, f1.TotalBytes)
	}
	if f1.TLSSNI != "github.com" {
		t.Errorf("expected TLSSNI github.com, got %s", f1.TLSSNI)
	}

	// Reverse packet (Server -> Client)
	t1 := t0.Add(50 * time.Millisecond)
	p2 := &cbridge.PacketMeta{
		Timestamp:  t1,
		Protocol:   "TCP",
		SrcIP:      "140.82.112.4",
		DstIP:      "192.168.1.50",
		SrcPort:    443,
		DstPort:    45000,
		PacketSize: 1200,
		Service:    "HTTPS",
	}

	f2 := mgr.Ingest(p2)
	if f2 != f1 {
		t.Fatalf("expected f2 to point to same aggregate flow as f1")
	}

	if f2.TotalPackets != 2 || f2.TotalBytes != 1350 {
		t.Errorf("expected 2 pkts and 1350 bytes, got %d pkts %d bytes", f2.TotalPackets, f2.TotalBytes)
	}
	if f2.PacketsInitiator != 1 || f2.BytesInitiator != 150 {
		t.Errorf("expected initiator 1 pkt 150 bytes, got %d pkts %d bytes", f2.PacketsInitiator, f2.BytesInitiator)
	}
	if f2.PacketsResponder != 1 || f2.BytesResponder != 1200 {
		t.Errorf("expected responder 1 pkt 1200 bytes, got %d pkts %d bytes", f2.PacketsResponder, f2.BytesResponder)
	}
	if f2.Duration() < 40*time.Millisecond {
		t.Errorf("expected duration >= 40ms, got %v", f2.Duration())
	}
}

func TestFlowTerminationTCPFinAndSweep(t *testing.T) {
	mgr := NewManager(100*time.Millisecond, 500*time.Millisecond)
	defer mgr.Close()

	t0 := time.Now().UTC()
	p := &cbridge.PacketMeta{
		Timestamp:  t0,
		Protocol:   "TCP",
		SrcIP:      "10.0.0.1",
		DstIP:      "10.0.0.2",
		SrcPort:    8080,
		DstPort:    9090,
		PacketSize: 60,
		TCPFlags:   0x01, // FIN
	}

	f := mgr.Ingest(p)
	if f.State != "CLOSED" {
		t.Errorf("expected flow state CLOSED after FIN, got %s", f.State)
	}

	// Active flows should contain 1 flow before sweep
	if len(mgr.GetActiveFlows()) != 1 {
		t.Fatalf("expected 1 active flow before sweep")
	}

	// Trigger sweep
	mgr.sweep(t0.Add(1 * time.Second))

	// Flow should be evacuated from active map into history
	if len(mgr.GetActiveFlows()) != 0 {
		t.Errorf("expected 0 active flows after sweep")
	}

	stats := mgr.GetStats()
	if stats.ClosedFlows != 1 {
		t.Errorf("expected 1 closed flow in stats, got %d", stats.ClosedFlows)
	}
}

func TestTopFlowsSortingAndSummary(t *testing.T) {
	mgr := NewManager(10*time.Second, 60*time.Second)
	defer mgr.Close()

	now := time.Now().UTC()
	mgr.Ingest(&cbridge.PacketMeta{
		Timestamp:  now,
		Protocol:   "TCP",
		SrcIP:      "1.1.1.1",
		DstIP:      "2.2.2.2",
		SrcPort:    1000,
		DstPort:    80,
		PacketSize: 100,
		HTTPMethod: "GET",
		HTTPHost:   "example.com",
	})

	mgr.Ingest(&cbridge.PacketMeta{
		Timestamp:  now,
		Protocol:   "UDP",
		SrcIP:      "3.3.3.3",
		DstIP:      "8.8.8.8",
		SrcPort:    2000,
		DstPort:    53,
		PacketSize: 500,
		DNSQuery:   "api.org",
	})

	top := mgr.GetTopFlows(1)
	if len(top) != 1 {
		t.Fatalf("expected 1 top flow")
	}
	if top[0].TotalBytes != 500 {
		t.Errorf("expected top flow with 500 bytes, got %d", top[0].TotalBytes)
	}

	summary := FormatFlowSummary(top[0])
	if summary == "" {
		t.Errorf("expected non-empty summary")
	}
}

