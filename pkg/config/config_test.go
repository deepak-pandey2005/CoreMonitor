package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected DefaultConfig to be valid, got: %v", err)
	}
}

func TestConfigValidationErrors(t *testing.T) {
	// 1. Invalid interface
	c1 := DefaultConfig()
	c1.Network.Interface = ""
	if err := c1.Validate(); err == nil {
		t.Errorf("expected error for empty network.interface")
	}

	// 2. Invalid snaplen
	c2 := DefaultConfig()
	c2.Network.Snaplen = 0
	if err := c2.Validate(); err == nil {
		t.Errorf("expected error for zero snaplen")
	}

	// 3. Invalid influx flush interval
	c3 := DefaultConfig()
	c3.InfluxDB.FlushIntervalSeconds = -1
	if err := c3.Validate(); err == nil {
		t.Errorf("expected error for negative flush_interval_seconds")
	}

	// 4. Invalid Prometheus endpoint
	c4 := DefaultConfig()
	c4.Prometheus.Endpoint = "invalid_endpoint_no_slash"
	if err := c4.Validate(); err == nil {
		t.Errorf("expected error for endpoint without leading slash")
	}

	// 5. Invalid flow timeouts
	c5 := DefaultConfig()
	c5.Flow.IdleTimeoutSeconds = 0
	if err := c5.Validate(); err == nil {
		t.Errorf("expected error for zero idle_timeout_seconds")
	}
}

func TestLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	content := `
network:
  interface: "eth1"
  snaplen: 1500
storage:
  pcap_enabled: false
  csv_enabled: false
influxdb:
  enabled: false
ids:
  enabled: true
  port_scan_threshold: 10
  port_scan_window_seconds: 5
  syn_flood_threshold: 50
  syn_flood_window_seconds: 2
  icmp_flood_threshold: 20
  icmp_flood_window_seconds: 2
prometheus:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("failed to load valid config: %v", err)
	}

	if loaded.Network.Interface != "eth1" {
		t.Errorf("expected interface eth1, got %s", loaded.Network.Interface)
	}
	if loaded.Network.Snaplen != 1500 {
		t.Errorf("expected snaplen 1500, got %d", loaded.Network.Snaplen)
	}
}
