package metrics

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/config"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/engine"
)

func TestPrometheusMetricsServer(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "tests", "fixtures", "attack_sample.pcap")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skipf("fixture %s not found", fixturePath)
	}

	tempDir, err := os.MkdirTemp("", "cmonitor_prom_test")
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
		t.Fatalf("failed to open fixture: %v", err)
	}

	eng, err := engine.NewEngine(cfg, capHandle)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer eng.Stop()

	// Run capture loop to populate stats
	if err := eng.ProcessLoop(); err != nil {
		t.Fatalf("process loop failed: %v", err)
	}

	promCfg := Config{
		Enabled:    true,
		ListenAddr: "127.0.0.1:0", // Dynamic available port
		Endpoint:   "/metrics",
	}

	srv := NewServer(promCfg, eng)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start prometheus server: %v", err)
	}
	defer func() { _ = srv.Stop() }()

	time.Sleep(50 * time.Millisecond)
	addr := srv.Addr()

	// 1. Check /healthz
	resp, err := http.Get(fmt.Sprintf("http://%s/healthz", addr))
	if err != nil {
		t.Fatalf("failed to query healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK from healthz, got %d", resp.StatusCode)
	}

	// 2. Check /metrics
	mResp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
	if err != nil {
		t.Fatalf("failed to scrape /metrics: %v", err)
	}
	defer mResp.Body.Close()

	if mResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK from /metrics, got %d", mResp.StatusCode)
	}

	contentType := mResp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("expected text/plain content type, got %s", contentType)
	}

	body, err := io.ReadAll(mResp.Body)
	if err != nil {
		t.Fatalf("failed to read /metrics body: %v", err)
	}
	bodyStr := string(body)

	expectedMetrics := []string{
		"coremonitor_packets_total",
		"coremonitor_bytes_total",
		"coremonitor_packets_per_second",
		"coremonitor_bytes_per_second",
		"coremonitor_protocol_packets_total{protocol=",
		"coremonitor_alerts_total",
		"coremonitor_ips_banned_hosts",
		"coremonitor_active_flows",
		"coremonitor_flows_total",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(bodyStr, metric) {
			t.Errorf("missing expected prometheus metric %q in output:\n%s", metric, bodyStr)
		}
	}
}

