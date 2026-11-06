package ips

import (
	"fmt"
	"sync"
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

func TestIPSCIDRWhitelistAndIPv6(t *testing.T) {
	cfg := Config{
		Enabled:            true,
		Mode:               "simulate",
		BanDurationSeconds: 10,
		MinSeverity:        "LOW",
		Whitelist: []string{
			"192.168.10.0/24",
			"2001:db8::/32",
			"10.0.0.5",
		},
	}

	mgr := NewManager(cfg)
	defer mgr.Cleanup()

	// 1. IP in CIDR whitelist
	if mgr.isWhitelisted("192.168.10.45") != true {
		t.Errorf("expected 192.168.10.45 to be whitelisted by CIDR")
	}
	// IP outside CIDR whitelist
	if mgr.isWhitelisted("192.168.11.45") != false {
		t.Errorf("expected 192.168.11.45 to NOT be whitelisted")
	}

	// 2. IPv6 in CIDR whitelist
	if mgr.isWhitelisted("2001:db8:1234::1") != true {
		t.Errorf("expected 2001:db8:1234::1 to be whitelisted by IPv6 CIDR")
	}
	// IPv6 outside CIDR whitelist
	if mgr.isWhitelisted("2001:db9::1") != false {
		t.Errorf("expected 2001:db9::1 to NOT be whitelisted")
	}

	// 3. IPv6 ban test
	ipv6Target := "2607:f8b0:4005:805::200e"
	alertIPv6 := cbridge.Alert{
		Severity:  "HIGH",
		AlertType: "SYN_FLOOD",
		SrcIP:     ipv6Target,
	}
	if !mgr.HandleAlert(alertIPv6) {
		t.Errorf("expected IPv6 alert to trigger ban")
	}
	if !mgr.IsBanned(ipv6Target) {
		t.Errorf("expected %s to be banned", ipv6Target)
	}
	if !mgr.Unban(ipv6Target) {
		t.Errorf("expected %s unban to succeed", ipv6Target)
	}
	if mgr.IsBanned(ipv6Target) {
		t.Errorf("expected %s to no longer be banned", ipv6Target)
	}
}

func TestIPSManagerConcurrentCleanup(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Mode:    "simulate",
	}
	mgr := NewManager(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.Cleanup()
		}()
	}
	wg.Wait()
}

func TestIPSInactivePruning(t *testing.T) {
	cfg := Config{
		Enabled:            false, // no background goroutines needed for this unit test
		Mode:               "simulate",
		BanDurationSeconds: 100,
	}
	mgr := NewManagerWithCapacity(cfg, 10)

	// Ban 10 hosts
	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("192.168.1.%d", 100+i)
		mgr.Ban(ip, "test attack", "HIGH")
	}

	if mgr.TotalTracked() != 10 {
		t.Fatalf("expected 10 tracked hosts, got %d", mgr.TotalTracked())
	}

	// Unban 4 of them
	for i := 0; i < 4; i++ {
		ip := fmt.Sprintf("192.168.1.%d", 100+i)
		mgr.Unban(ip)
	}

	// Ban 3 new hosts - should trigger pruneInactiveLocked
	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("10.0.0.%d", 50+i)
		mgr.Ban(ip, "new attack", "HIGH")
	}

	if mgr.TotalTracked() > 10 {
		t.Errorf("expected total tracked hosts <= 10 after pruning inactive entries, got %d", mgr.TotalTracked())
	}

	// Verify the remaining active hosts are still present
	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("10.0.0.%d", 50+i)
		if !mgr.IsBanned(ip) {
			t.Errorf("expected newly banned host %s to be active", ip)
		}
	}
}

