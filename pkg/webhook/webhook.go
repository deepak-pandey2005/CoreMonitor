package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

// Config holds webhook endpoints and notification thresholds.
type Config struct {
	Enabled         bool   `yaml:"enabled"`
	DiscordURL      string `yaml:"discord_url"`
	SlackURL        string `yaml:"slack_url"`
	TelegramToken   string `yaml:"telegram_bot_token"`
	TelegramChatID  string `yaml:"telegram_chat_id"`
	MinSeverity     string `yaml:"min_severity"`     // "HIGH" or "CRITICAL"
	CooldownSeconds int    `yaml:"cooldown_seconds"` // Suppress repetitive alerts per (IP, type)
}

// DefaultConfig returns safe default webhook settings.
func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		MinSeverity:     "HIGH",
		CooldownSeconds: 30,
	}
}

const DefaultMaxCooldownEntries = 10000

// Dispatcher manages non-blocking async alert delivery to external webhooks.
type Dispatcher struct {
	cfg        Config
	client     *http.Client
	alertQueue chan alertJob
	stopChan   chan struct{}
	wg         sync.WaitGroup

	mu         sync.Mutex
	cooldowns  map[string]time.Time
	maxEntries int
}

type alertJob struct {
	alert  cbridge.Alert
	jailed bool
}

// NewDispatcher creates an async webhook dispatcher with a background worker pool.
func NewDispatcher(cfg Config) *Dispatcher {
	return NewDispatcherWithCapacity(cfg, DefaultMaxCooldownEntries)
}

// NewDispatcherWithCapacity creates an async webhook dispatcher with a bounded cooldown capacity.
func NewDispatcherWithCapacity(cfg Config, maxEntries int) *Dispatcher {
	if cfg.CooldownSeconds <= 0 {
		cfg.CooldownSeconds = 30
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = "HIGH"
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxCooldownEntries
	}

	d := &Dispatcher{
		cfg:        cfg,
		client:     &http.Client{Timeout: 5 * time.Second},
		alertQueue: make(chan alertJob, 256),
		stopChan:   make(chan struct{}),
		cooldowns:  make(map[string]time.Time),
		maxEntries: maxEntries,
	}

	if cfg.Enabled {
		d.wg.Add(1)
		go d.worker()
	}

	return d
}

// Dispatch queues an alert for transmission if it passes severity and cooldown filters.
func (d *Dispatcher) Dispatch(alert cbridge.Alert, isJailed bool) bool {
	if !d.cfg.Enabled {
		return false
	}

	if !d.passesSeverity(alert.Severity) {
		return false
	}

	// Check Cooldown
	cooldownKey := fmt.Sprintf("%s:%s", alert.SrcIP, alert.AlertType)
	cooldownDur := time.Duration(d.cfg.CooldownSeconds) * time.Second
	d.mu.Lock()
	now := time.Now()
	lastSent, exists := d.cooldowns[cooldownKey]
	if exists && now.Sub(lastSent) < cooldownDur {
		d.mu.Unlock()
		return false
	}

	if len(d.cooldowns) >= d.maxEntries {
		// Prune expired entries
		for k, t := range d.cooldowns {
			if now.Sub(t) >= cooldownDur {
				delete(d.cooldowns, k)
			}
		}
		// If still at capacity, evict a batch
		if len(d.cooldowns) >= d.maxEntries {
			evictCount := d.maxEntries / 4
			if evictCount == 0 {
				evictCount = 1
			}
			for k := range d.cooldowns {
				delete(d.cooldowns, k)
				evictCount--
				if evictCount <= 0 {
					break
				}
			}
		}
	}

	d.cooldowns[cooldownKey] = now
	d.mu.Unlock()

	select {
	case d.alertQueue <- alertJob{alert: alert, jailed: isJailed}:
		return true
	default:
		// Queue full, drop alert rather than blocking datapath
		return false
	}
}

// CooldownLen returns the current number of tracked cooldown keys.
func (d *Dispatcher) CooldownLen() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.cooldowns)
}

func (d *Dispatcher) passesSeverity(sev string) bool {
	if d.cfg.MinSeverity == "CRITICAL" {
		return sev == "CRITICAL"
	}
	// "HIGH" allows HIGH and CRITICAL
	return sev == "HIGH" || sev == "CRITICAL"
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()

	for {
		select {
		case <-d.stopChan:
			// Drain remaining alerts
			for {
				select {
				case job := <-d.alertQueue:
					d.send(job)
				default:
					return
				}
			}
		case job := <-d.alertQueue:
			d.send(job)
		}
	}
}

func (d *Dispatcher) send(job alertJob) {
	if d.cfg.DiscordURL != "" {
		_ = d.sendDiscord(d.cfg.DiscordURL, job)
	}
	if d.cfg.SlackURL != "" {
		_ = d.sendSlack(d.cfg.SlackURL, job)
	}
	if d.cfg.TelegramToken != "" && d.cfg.TelegramChatID != "" {
		_ = d.sendTelegram(job)
	}
}

// Discord Webhook Payload
type discordPayload struct {
	Username  string         `json:"username"`
	AvatarURL string         `json:"avatar_url"`
	Embeds    []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields"`
	Footer      discordFooter  `json:"footer"`
	Timestamp   string         `json:"timestamp"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func (d *Dispatcher) sendDiscord(url string, job alertJob) error {
	a := job.alert
	color := 0xFFA500 // Orange for HIGH
	if a.Severity == "CRITICAL" {
		color = 0xFF0000 // Red for CRITICAL
	}

	src := fmt.Sprintf("%s %s:%d (%s)", a.SrcFlag, a.SrcIP, a.SrcPort, a.SrcCountry)
	dst := fmt.Sprintf("%s %s:%d (%s)", a.DstFlag, a.DstIP, a.DstPort, a.DstCountry)
	defense := "⚠️ Monitored / Simulated"
	if job.jailed {
		defense = "🛡️ JAILED (iptables DROP active)"
	}

	payload := discordPayload{
		Username:  "CoreMonitor IDS/IPS",
		AvatarURL: "https://raw.githubusercontent.com/deepak-pandey2005/CoreMonitor/main/assets/shield.png",
		Embeds: []discordEmbed{
			{
				Title:       fmt.Sprintf("🚨 Security Threat Detected: [%s] %s", a.Severity, a.AlertType),
				Description: a.Message,
				Color:       color,
				Fields: []discordField{
					{Name: "Attacker / Source", Value: src, Inline: true},
					{Name: "Target / Destination", Value: dst, Inline: true},
					{Name: "Protocol", Value: a.Protocol, Inline: true},
					{Name: "Active Defense Status", Value: defense, Inline: true},
					{Name: "Threat Signature", Value: a.Details, Inline: false},
				},
				Footer:    discordFooter{Text: "CoreMonitor Network Intrusion Detection & Prevention System"},
				Timestamp: a.Timestamp.Format(time.RFC3339),
			},
		},
	}

	return d.postJSON(url, payload)
}

// Slack Incoming Webhook Payload
type slackPayload struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type string     `json:"type"`
	Text *slackText `json:"text,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (d *Dispatcher) sendSlack(url string, job alertJob) error {
	a := job.alert
	defense := "⚠️ Simulated"
	if job.jailed {
		defense = "🛡️ Active Defense Jailed Host"
	}

	headerText := fmt.Sprintf("🚨 *[%s] CoreMonitor Alert: %s*", a.Severity, a.AlertType)
	bodyText := fmt.Sprintf("*Attacker:* %s %s:%d (%s)\n*Target:* %s %s:%d (%s)\n*Message:* %s\n*Defense:* %s",
		a.SrcFlag, a.SrcIP, a.SrcPort, a.SrcCountry,
		a.DstFlag, a.DstIP, a.DstPort, a.DstCountry,
		a.Message, defense)

	payload := slackPayload{
		Text: headerText,
		Blocks: []slackBlock{
			{Type: "header", Text: &slackText{Type: "plain_text", Text: headerText}},
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: bodyText}},
		},
	}

	return d.postJSON(url, payload)
}

func (d *Dispatcher) sendTelegram(job alertJob) error {
	a := job.alert
	defense := "⚠️ Monitored"
	if job.jailed {
		defense = "🛡️ JAILED (DROP)"
	}

	msg := fmt.Sprintf("🚨 *CoreMonitor Security Alert*\n\n*Severity:* %s\n*Threat:* %s\n*Attacker:* %s `%s:%d` (%s)\n*Target:* %s `%s:%d` (%s)\n*Protocol:* %s\n*Defense:* %s\n*Message:* %s",
		a.Severity, a.AlertType,
		a.SrcFlag, a.SrcIP, a.SrcPort, a.SrcCountry,
		a.DstFlag, a.DstIP, a.DstPort, a.DstCountry,
		a.Protocol, defense, a.Message)

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", d.cfg.TelegramToken)
	reqBody := map[string]string{
		"chat_id":    d.cfg.TelegramChatID,
		"text":       msg,
		"parse_mode": "Markdown",
	}

	return d.postJSON(apiURL, reqBody)
}

func (d *Dispatcher) postJSON(targetURL string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook responded with HTTP %d", resp.StatusCode)
	}
	return nil
}

// Close gracefully flushes remaining jobs and stops workers.
func (d *Dispatcher) Close() {
	select {
	case <-d.stopChan:
		return
	default:
		close(d.stopChan)
		d.wg.Wait()
	}
}
