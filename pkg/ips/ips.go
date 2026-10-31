package ips

import (
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

type Config struct {
	Enabled            bool     `yaml:"enabled"`
	Mode               string   `yaml:"mode"` // "block" or "simulate"
	BanDurationSeconds int      `yaml:"ban_duration_seconds"`
	MinSeverity        string   `yaml:"min_severity"` // "HIGH" or "CRITICAL"
	Whitelist          []string `yaml:"whitelist"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:            true,
		Mode:               "simulate", // Safe default: simulate mode
		BanDurationSeconds: 600,        // 10 minutes
		MinSeverity:        "HIGH",
		Whitelist: []string{
			"127.0.0.1",
			"::1",
			"192.168.1.1",
			"192.168.0.1",
		},
	}
}

type BannedHost struct {
	IP        string
	Reason    string
	Severity  string
	BannedAt  time.Time
	ExpiresAt time.Time
	Active    bool
}

type Manager struct {
	cfg        Config
	mu         sync.RWMutex
	banned     map[string]*BannedHost
	whitelist  map[string]bool
	stopChan   chan struct{}
	actionChan chan string
}

func NewManager(cfg Config) *Manager {
	m := &Manager{
		cfg:        cfg,
		banned:     make(map[string]*BannedHost),
		whitelist:  make(map[string]bool),
		stopChan:   make(chan struct{}),
		actionChan: make(chan string, 100),
	}

	for _, ip := range cfg.Whitelist {
		m.whitelist[ip] = true
	}

	if cfg.Enabled {
		go m.expirationWorker()
	}

	return m
}

func (m *Manager) isWhitelisted(ipStr string) bool {
	if m.whitelist[ipStr] {
		return true
	}
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() {
		return true
	}
	return false
}

func (m *Manager) HandleAlert(a cbridge.Alert) bool {
	if !m.cfg.Enabled {
		return false
	}

	targetIP := a.SrcIP
	if targetIP == "" || targetIP == "unknown" {
		return false
	}

	if m.isWhitelisted(targetIP) {
		return false
	}

	// Check severity threshold
	if m.cfg.MinSeverity == "CRITICAL" && a.Severity != "CRITICAL" {
		return false
	}
	if m.cfg.MinSeverity == "HIGH" && a.Severity != "CRITICAL" && a.Severity != "HIGH" {
		return false
	}

	return m.Ban(targetIP, a.AlertType+": "+a.Message, a.Severity)
}

func (m *Manager) Ban(ip, reason, severity string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isWhitelisted(ip) {
		return false
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(m.cfg.BanDurationSeconds) * time.Second)

	if host, exists := m.banned[ip]; exists && host.Active {
		// Extend ban duration
		host.ExpiresAt = expiresAt
		host.Reason = reason
		return true
	}

	m.banned[ip] = &BannedHost{
		IP:        ip,
		Reason:    reason,
		Severity:  severity,
		BannedAt:  now,
		ExpiresAt: expiresAt,
		Active:    true,
	}

	if m.cfg.Mode == "block" {
		m.execIptables("-I", "INPUT", "-s", ip, "-j", "DROP")
		m.execIptables("-I", "FORWARD", "-s", ip, "-j", "DROP")
	}

	select {
	case m.actionChan <- fmt.Sprintf("[IPS] Banned %s (mode: %s, duration: %ds): %s", ip, m.cfg.Mode, m.cfg.BanDurationSeconds, reason):
	default:
	}

	return true
}

func (m *Manager) Unban(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	host, exists := m.banned[ip]
	if !exists || !host.Active {
		return false
	}

	host.Active = false

	if m.cfg.Mode == "block" {
		m.execIptables("-D", "INPUT", "-s", ip, "-j", "DROP")
		m.execIptables("-D", "FORWARD", "-s", ip, "-j", "DROP")
	}

	select {
	case m.actionChan <- fmt.Sprintf("[IPS] Unbanned %s (ban expired)", ip):
	default:
	}

	return true
}

func (m *Manager) IsBanned(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	host, exists := m.banned[ip]
	return exists && host.Active
}

func (m *Manager) GetBannedHosts() []BannedHost {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]BannedHost, 0, len(m.banned))
	for _, h := range m.banned {
		if h.Active {
			res = append(res, *h)
		}
	}
	return res
}

func (m *Manager) ActionLog() <-chan string {
	return m.actionChan
}

func (m *Manager) expirationWorker() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			var toUnban []string

			m.mu.RLock()
			for ip, h := range m.banned {
				if h.Active && now.After(h.ExpiresAt) {
					toUnban = append(toUnban, ip)
				}
			}
			m.mu.RUnlock()

			for _, ip := range toUnban {
				m.Unban(ip)
			}

		case <-m.stopChan:
			return
		}
	}
}

func (m *Manager) execIptables(args ...string) {
	cmd := exec.Command("iptables", args...)
	_ = cmd.Run()
}

func (m *Manager) Cleanup() {
	if m.cfg.Enabled {
		close(m.stopChan)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg.Mode == "block" {
		for ip, h := range m.banned {
			if h.Active {
				m.execIptables("-D", "INPUT", "-s", ip, "-j", "DROP")
				m.execIptables("-D", "FORWARD", "-s", ip, "-j", "DROP")
				h.Active = false
			}
		}
	}
}
