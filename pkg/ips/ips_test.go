package ips

import (
	"testing"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

func TestIPSManager(t *testing.T) {
	cfg := Config{
		Enabled:            true,
		Mode:               "simulate",
		BanDurationSeconds: 1, // 1 second for fast test
		MinSeverity:        "HIGH",
		Whitelist: []string{
			"127.0.0.1",
			"192.168.1.1",
		},
	}

	mgr := NewManager(cfg)
	defer mgr.Cleanup()

	// 1. Whitelisted IP should NOT be banned
	alertWhitelist := cbridge.Alert{
		Severity:  "CRITICAL",
		AlertType: "SYN_FLOOD",
		SrcIP:     "127.0.0.1",
	}
	if mgr.HandleAlert(alertWhitelist) {
		t.Errorf("whitelisted 127.0.0.1 should not be banned")
	}

	// 2. Low severity alert should NOT trigger ban when threshold is HIGH
	alertLow := cbridge.Alert{
		Severity:  "MEDIUM",
		AlertType: "SUSPICIOUS_PORT",
		SrcIP:     "192.168.1.50",
	}
	if mgr.HandleAlert(alertLow) {
		t.Errorf("MEDIUM severity alert should not trigger ban when threshold is HIGH")
	}
	if mgr.IsBanned("192.168.1.50") {
		t.Errorf("192.168.1.50 should not be banned")
	}

	// 3. High severity alert SHOULD trigger ban
	alertHigh := cbridge.Alert{
		Severity:  "HIGH",
		AlertType: "PORT_SCAN_SYN",
		SrcIP:     "192.168.1.200",
		Message:   "Probed 15 ports",
	}
	if !mgr.HandleAlert(alertHigh) {
		t.Errorf("expected 192.168.1.200 to be banned")
	}
	if !mgr.IsBanned("192.168.1.200") {
		t.Errorf("192.168.1.200 should be marked as banned")
	}

	bannedList := mgr.GetBannedHosts()
	if len(bannedList) != 1 || bannedList[0].IP != "192.168.1.200" {
		t.Errorf("expected 1 banned host with IP 192.168.1.200, got %+v", bannedList)
	}

	// 4. Test auto-unban expiration (wait 1.5s for 1s ban to expire)
	time.Sleep(1500 * time.Millisecond)
	// trigger check or wait for worker
	for i := 0; i < 10; i++ {
		if !mgr.IsBanned("192.168.1.200") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if mgr.IsBanned("192.168.1.200") {
		t.Errorf("192.168.1.200 should have been unbanned after expiration")
	}
}
