package engine

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/config"
)

func TestEngineOfflinePCAPInspection(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "tests", "fixtures", "attack_sample.pcap")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skipf("fixture %s not found", fixturePath)
	}

	tempDir, err := os.MkdirTemp("", "cmonitor_engine_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := *config.DefaultConfig()
	cfg.Storage.CSVDir = tempDir
	cfg.Storage.PCAPDir = tempDir
	cfg.InfluxDB.Enabled = false

	capHandle, err := cbridge.OpenOffline(fixturePath, "")
	if err != nil {
		t.Fatalf("failed to open fixture PCAP: %v", err)
	}

	eng, err := NewEngine(cfg, capHandle)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer eng.Stop()

	if err := eng.ProcessLoop(); err != nil {
		t.Fatalf("process loop error: %v", err)
	}

	stats := eng.GetStats()
	if stats.TotalPackets < 85 {
		t.Errorf("expected at least 85 packets, got %d", stats.TotalPackets)
	}

	if stats.FlowStats.TotalFlowsCreated == 0 {
		t.Errorf("expected flow manager to track flows, got 0 created")
	}

	if len(stats.RecentAlerts) != 10 {
		t.Errorf("expected 10 alerts, got %d", len(stats.RecentAlerts))
	}

	alertTypes := make(map[string]bool)
	for _, a := range stats.RecentAlerts {
		alertTypes[a.AlertType] = true
	}

	expectedTypes := []string{
		"SUSPICIOUS_PORT",
		"PORT_SCAN_SYN",
		"XMAS_SCAN",
		"NULL_SCAN",
		"BLACKLISTED_IP",
		"DNS_TUNNEL_ANOMALY",
		"ICMP_FLOOD",
	}

	for _, exp := range expectedTypes {
		if !alertTypes[exp] {
			t.Errorf("missing expected alert type: %s", exp)
		}
	}
}

func TestEngineWebhookDispatch(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "tests", "fixtures", "attack_sample.pcap")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skipf("fixture %s not found", fixturePath)
	}

	var webhookCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tempDir, err := os.MkdirTemp("", "cmonitor_webhook_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := *config.DefaultConfig()
	cfg.Storage.CSVDir = tempDir
	cfg.Storage.PCAPDir = tempDir
	cfg.InfluxDB.Enabled = false
	cfg.Webhook.Enabled = true
	cfg.Webhook.DiscordURL = server.URL
	cfg.Webhook.MinSeverity = "HIGH"
	cfg.Webhook.CooldownSeconds = 1

	capHandle, err := cbridge.OpenOffline(fixturePath, "")
	if err != nil {
		t.Fatalf("failed to open fixture PCAP: %v", err)
	}

	eng, err := NewEngine(cfg, capHandle)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer eng.Stop()

	if err := eng.ProcessLoop(); err != nil {
		t.Fatalf("process loop error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&webhookCount) == 0 {
		t.Errorf("expected webhook alerts to be received by mock server, got 0")
	}
}
