package siem

// Config defines the configuration for the SIEM CEF/Syslog exporter.
type Config struct {
	Enabled     bool   `yaml:"enabled"`
	Format      string `yaml:"format"`       // "cef", "syslog-cef" (RFC 3164 with CEF), or "rfc5424"
	Transport   string `yaml:"transport"`    // "udp", "tcp", or "file"
	Address     string `yaml:"address"`      // "127.0.0.1:514"
	FilePath    string `yaml:"file_path"`    // "captures/siem_events.log"
	Facility    int    `yaml:"facility"`     // Syslog facility (default: 16 = local0)
	AppName     string `yaml:"app_name"`     // Syslog application name (default: "CoreMonitor")
	MinSeverity string `yaml:"min_severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL" (default: "LOW")
	QueueSize   int    `yaml:"queue_size"`   // Max non-blocking queue capacity (default: 1024)
}

// DefaultConfig provides standard enterprise SIEM exporter defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:     false,
		Format:      "cef",
		Transport:   "udp",
		Address:     "127.0.0.1:514",
		FilePath:    "captures/siem_events.log",
		Facility:    16, // local0
		AppName:     "CoreMonitor",
		MinSeverity: "LOW",
		QueueSize:   1024,
	}
}

