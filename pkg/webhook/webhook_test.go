package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

func TestDiscordWebhookDelivery(t *testing.T) {
	var requestCount int32
	var receivedPayload discordPayload

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := Config{
		Enabled:         true,
		DiscordURL:      ts.URL,
		MinSeverity:     "HIGH",
		CooldownSeconds: 10,
	}

	dispatcher := NewDispatcher(cfg)
	defer dispatcher.Close()

	alert := cbridge.Alert{
		Timestamp:  time.Now().UTC(),
		Severity:   "CRITICAL",
		AlertType:  "PORT_SCAN_SYN",
		Message:    "SYN scan detected",
		SrcIP:      "198.51.100.23",
		SrcPort:    55432,
		SrcFlag:    "🇺🇸",
		SrcCountry: "US",
		DstIP:      "192.168.1.50",
		DstPort:    80,
		DstFlag:    "🏠",
		DstCountry: "LAN",
		Protocol:   "TCP",
		Details:    "15 distinct ports probed",
	}

	ok := dispatcher.Dispatch(alert, true)
	if !ok {
		t.Fatalf("expected alert to be dispatched successfully")
	}

	// Wait for async transmission
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Fatalf("expected 1 webhook request, got %d", atomic.LoadInt32(&requestCount))
	}

	if len(receivedPayload.Embeds) == 0 {
		t.Fatalf("expected discord embed in payload")
	}

	embed := receivedPayload.Embeds[0]
	if embed.Color != 0xFF0000 {
		t.Errorf("expected red color 0xFF0000 for CRITICAL, got %X", embed.Color)
	}

	foundDefense := false
	for _, f := range embed.Fields {
		if f.Name == "Active Defense Status" && f.Value == "🛡️ JAILED (iptables DROP active)" {
			foundDefense = true
		}
	}
	if !foundDefense {
		t.Errorf("expected jailed active defense field in embed")
	}
}

func TestSlackWebhookDelivery(t *testing.T) {
	var requestCount int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := Config{
		Enabled:         true,
		SlackURL:        ts.URL,
		MinSeverity:     "HIGH",
		CooldownSeconds: 10,
	}

	dispatcher := NewDispatcher(cfg)
	defer dispatcher.Close()

	alert := cbridge.Alert{
		Timestamp: time.Now().UTC(),
		Severity:  "HIGH",
		AlertType: "DNS_TUNNEL_ANOMALY",
		Message:   "Long query detected",
		SrcIP:     "192.168.1.100",
	}

	dispatcher.Dispatch(alert, false)
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Fatalf("expected 1 slack request, got %d", atomic.LoadInt32(&requestCount))
	}
}

func TestCooldownSuppression(t *testing.T) {
	var requestCount int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := Config{
		Enabled:         true,
		DiscordURL:      ts.URL,
		MinSeverity:     "HIGH",
		CooldownSeconds: 5,
	}

	dispatcher := NewDispatcher(cfg)
	defer dispatcher.Close()

	alert := cbridge.Alert{
		Timestamp: time.Now().UTC(),
		Severity:  "HIGH",
		AlertType: "ICMP_FLOOD",
		SrcIP:     "192.168.1.220",
	}

	// First dispatch should pass
	if !dispatcher.Dispatch(alert, false) {
		t.Errorf("first dispatch should succeed")
	}

	// Immediate second dispatch with same IP & type should be throttled by cooldown
	if dispatcher.Dispatch(alert, false) {
		t.Errorf("second dispatch should be suppressed by cooldown")
	}

	time.Sleep(100 * time.Millisecond)
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected only 1 request due to cooldown, got %d", atomic.LoadInt32(&requestCount))
	}
}

func TestSeverityFiltering(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		DiscordURL:      "http://example.com/webhook",
		MinSeverity:     "HIGH",
		CooldownSeconds: 10,
	}

	dispatcher := NewDispatcher(cfg)
	defer dispatcher.Close()

	medAlert := cbridge.Alert{
		Timestamp: time.Now().UTC(),
		Severity:  "MEDIUM",
		AlertType: "SUSPICIOUS_PORT",
		SrcIP:     "192.168.1.120",
	}

	if dispatcher.Dispatch(medAlert, false) {
		t.Errorf("expected MEDIUM alert to be dropped when MinSeverity=HIGH")
	}
}

func TestWebhookBoundedCooldownCache(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	capacity := 50
	cfg := Config{
		Enabled:         true,
		DiscordURL:      ts.URL,
		MinSeverity:     "HIGH",
		CooldownSeconds: 30,
	}

	dispatcher := NewDispatcherWithCapacity(cfg, capacity)
	defer dispatcher.Close()

	// Ingest 200 distinct IPs
	for i := 0; i < 200; i++ {
		alert := cbridge.Alert{
			Timestamp: time.Now().UTC(),
			Severity:  "HIGH",
			AlertType: "PORT_SCAN_SYN",
			SrcIP:     "10.0.0." + string(rune('0'+(i%10))) + string(rune('0'+((i/10)%10))),
		}
		_ = dispatcher.Dispatch(alert, false)
	}

	if dispatcher.CooldownLen() > capacity {
		t.Errorf("expected cooldown cache len <= %d, got %d", capacity, dispatcher.CooldownLen())
	}
}

