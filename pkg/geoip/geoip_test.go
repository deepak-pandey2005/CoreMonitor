package geoip

import (
	"fmt"
	"testing"
)

func TestCountryCodeToFlag(t *testing.T) {
	cases := []struct {
		cc   string
		flag string
	}{
		{"US", "🇺🇸"},
		{"DE", "🇩🇪"},
		{"IN", "🇮🇳"},
		{"FR", "🇫🇷"},
		{"GB", "🇬🇧"},
		{"LAN", "🏠"},
	}

	for _, c := range cases {
		got := CountryCodeToFlag(c.cc)
		if got != c.flag {
			t.Errorf("CountryCodeToFlag(%s) = %s; want %s", c.cc, got, c.flag)
		}
	}
}

func TestLookup(t *testing.T) {
	// Private LAN IP
	loc1 := Lookup("192.168.1.105")
	if !loc1.IsPrivate || loc1.CountryCode != "LAN" || loc1.Flag != "🏠" {
		t.Errorf("expected LAN location for 192.168.1.105, got %+v", loc1)
	}

	// Loopback
	locLoop := Lookup("127.0.0.1")
	if !locLoop.IsPrivate || locLoop.CountryCode != "LAN" {
		t.Errorf("expected LAN for 127.0.0.1, got %+v", locLoop)
	}

	// Public Google DNS
	locGoogle := Lookup("8.8.8.8")
	if locGoogle.CountryCode != "US" || locGoogle.Flag != "🇺🇸" {
		t.Errorf("expected US for 8.8.8.8, got %+v", locGoogle)
	}

	// Tor exit node range (Germany)
	locTor := Lookup("185.220.101.5")
	if locTor.CountryCode != "DE" || locTor.Flag != "🇩🇪" {
		t.Errorf("expected DE for 185.220.101.5, got %+v", locTor)
	}
}

func TestResolverBoundedCache(t *testing.T) {
	capacity := 100
	res := NewResolverWithCapacity(capacity)

	for i := 0; i < 300; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		_ = res.Lookup(ip)
	}

	if res.CacheLen() > capacity {
		t.Errorf("expected cache len <= %d, got %d", capacity, res.CacheLen())
	}
}
