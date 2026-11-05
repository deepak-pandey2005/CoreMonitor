package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/ips"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/siem"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/webhook"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Network struct {
		Interface   string `yaml:"interface"`
		BPFFilter   string `yaml:"bpf_filter"`
		Promiscuous bool   `yaml:"promiscuous"`
		Snaplen     int    `yaml:"snaplen"`
	} `yaml:"network"`

	Storage struct {
		PCAPEnabled       bool   `yaml:"pcap_enabled"`
		PCAPDir           string `yaml:"pcap_dir"`
		PCAPRotateSeconds int    `yaml:"pcap_rotate_seconds"`
		CSVEnabled        bool   `yaml:"csv_enabled"`
		CSVDir            string `yaml:"csv_dir"`
		CSVRotateSeconds  int    `yaml:"csv_rotate_seconds"`
	} `yaml:"storage"`

	InfluxDB struct {
		Enabled              bool   `yaml:"enabled"`
		URL                  string `yaml:"url"`
		Token                string `yaml:"token"`
		Org                  string `yaml:"org"`
		Bucket               string `yaml:"bucket"`
		BatchSize            int    `yaml:"batch_size"`
		FlushIntervalSeconds int    `yaml:"flush_interval_seconds"`
	} `yaml:"influxdb"`

	IDS struct {
		Enabled                   bool   `yaml:"enabled"`
		PortScanThreshold         int    `yaml:"port_scan_threshold"`
		PortScanWindowSeconds     int    `yaml:"port_scan_window_seconds"`
		SYNFloodThreshold         int    `yaml:"syn_flood_threshold"`
		SYNFloodWindowSeconds     int    `yaml:"syn_flood_window_seconds"`
		BandwidthSpikeBytesPerSec uint64 `yaml:"bandwidth_spike_bytes_per_sec"`
		BandwidthWindowSeconds    int    `yaml:"bandwidth_window_seconds"`
		DNSTunnelAnomalyLength    int    `yaml:"dns_tunnel_anomaly_length"`
		ICMPFloodThreshold        int    `yaml:"icmp_flood_threshold"`
		ICMPFloodWindowSeconds    int    `yaml:"icmp_flood_window_seconds"`
	} `yaml:"ids"`

	LiveDashboard bool `yaml:"live_dashboard"`

	IPS ips.Config `yaml:"ips"`

	Flow struct {
		Enabled              bool `yaml:"enabled"`
		IdleTimeoutSeconds   int  `yaml:"idle_timeout_seconds"`
		ActiveTimeoutSeconds int  `yaml:"active_timeout_seconds"`
	} `yaml:"flow"`

	Webhook webhook.Config `yaml:"webhook"`
	SIEM    siem.Config    `yaml:"siem"`

	Prometheus struct {
		Enabled    bool   `yaml:"enabled"`
		ListenAddr string `yaml:"listen_addr"`
		Endpoint   string `yaml:"endpoint"`
	} `yaml:"prometheus"`
}

func DefaultConfig() *Config {
	cfg := &Config{}
	cfg.Network.Interface = "wlan0"
	cfg.Network.Promiscuous = true
	cfg.Network.Snaplen = 65535

	cfg.Storage.PCAPEnabled = true
	cfg.Storage.PCAPDir = "captures"
	cfg.Storage.PCAPRotateSeconds = 3600
	cfg.Storage.CSVEnabled = true
	cfg.Storage.CSVDir = "captures"
	cfg.Storage.CSVRotateSeconds = 3600

	cfg.InfluxDB.Enabled = true
	cfg.InfluxDB.URL = "http://localhost:8086"
	cfg.InfluxDB.Token = "coremonitor-super-secret-auth-token"
	cfg.InfluxDB.Org = "coremonitor-org"
	cfg.InfluxDB.Bucket = "network_metrics"
	cfg.InfluxDB.BatchSize = 50
	cfg.InfluxDB.FlushIntervalSeconds = 2

	cfg.IDS.Enabled = true
	cfg.IDS.PortScanThreshold = 15
	cfg.IDS.PortScanWindowSeconds = 10
	cfg.IDS.SYNFloodThreshold = 100
	cfg.IDS.SYNFloodWindowSeconds = 2
	cfg.IDS.BandwidthSpikeBytesPerSec = 10000000 // 10 MB/s
	cfg.IDS.BandwidthWindowSeconds = 2
	cfg.IDS.DNSTunnelAnomalyLength = 60
	cfg.IDS.ICMPFloodThreshold = 50
	cfg.IDS.ICMPFloodWindowSeconds = 2

	cfg.LiveDashboard = true
	cfg.IPS = ips.DefaultConfig()

	cfg.Flow.Enabled = true
	cfg.Flow.IdleTimeoutSeconds = 30
	cfg.Flow.ActiveTimeoutSeconds = 120

	cfg.Webhook = webhook.DefaultConfig()
	cfg.SIEM = siem.DefaultConfig()

	cfg.Prometheus.Enabled = true
	cfg.Prometheus.ListenAddr = "0.0.0.0:2112"
	cfg.Prometheus.Endpoint = "/metrics"
	return cfg
}

func (c *Config) Validate() error {
	if c.Network.Interface == "" {
		return fmt.Errorf("network.interface cannot be empty")
	}
	if c.Network.Snaplen <= 0 {
		return fmt.Errorf("network.snaplen must be greater than 0, got %d", c.Network.Snaplen)
	}

	if c.Storage.PCAPEnabled {
		if c.Storage.PCAPDir == "" {
			return fmt.Errorf("storage.pcap_dir cannot be empty when PCAP is enabled")
		}
		if c.Storage.PCAPRotateSeconds <= 0 {
			return fmt.Errorf("storage.pcap_rotate_seconds must be > 0, got %d", c.Storage.PCAPRotateSeconds)
		}
	}
	if c.Storage.CSVEnabled {
		if c.Storage.CSVDir == "" {
			return fmt.Errorf("storage.csv_dir cannot be empty when CSV is enabled")
		}
		if c.Storage.CSVRotateSeconds <= 0 {
			return fmt.Errorf("storage.csv_rotate_seconds must be > 0, got %d", c.Storage.CSVRotateSeconds)
		}
	}

	if c.InfluxDB.Enabled {
		if c.InfluxDB.URL == "" {
			return fmt.Errorf("influxdb.url cannot be empty when InfluxDB is enabled")
		}
		if c.InfluxDB.BatchSize <= 0 {
			return fmt.Errorf("influxdb.batch_size must be > 0, got %d", c.InfluxDB.BatchSize)
		}
		if c.InfluxDB.FlushIntervalSeconds <= 0 {
			return fmt.Errorf("influxdb.flush_interval_seconds must be > 0, got %d", c.InfluxDB.FlushIntervalSeconds)
		}
	}

	if c.IDS.Enabled {
		if c.IDS.PortScanThreshold <= 0 || c.IDS.PortScanWindowSeconds <= 0 {
			return fmt.Errorf("ids.port_scan parameters must be > 0")
		}
		if c.IDS.SYNFloodThreshold <= 0 || c.IDS.SYNFloodWindowSeconds <= 0 {
			return fmt.Errorf("ids.syn_flood parameters must be > 0")
		}
		if c.IDS.ICMPFloodThreshold <= 0 || c.IDS.ICMPFloodWindowSeconds <= 0 {
			return fmt.Errorf("ids.icmp_flood parameters must be > 0")
		}
	}

	if c.Flow.Enabled {
		if c.Flow.IdleTimeoutSeconds <= 0 {
			return fmt.Errorf("flow.idle_timeout_seconds must be > 0, got %d", c.Flow.IdleTimeoutSeconds)
		}
		if c.Flow.ActiveTimeoutSeconds <= 0 {
			return fmt.Errorf("flow.active_timeout_seconds must be > 0, got %d", c.Flow.ActiveTimeoutSeconds)
		}
	}

	if c.Prometheus.Enabled {
		if c.Prometheus.ListenAddr == "" {
			return fmt.Errorf("prometheus.listen_addr cannot be empty when Prometheus is enabled")
		}
		if !strings.HasPrefix(c.Prometheus.Endpoint, "/") {
			return fmt.Errorf("prometheus.endpoint must start with '/', got %q", c.Prometheus.Endpoint)
		}
	}

	return nil
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}
