package config

import (
	"os"

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

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
