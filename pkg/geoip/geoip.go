package geoip

import (
	"net"
	"strings"
	"sync"
)

type Location struct {
	CountryCode string
	CountryName string
	Flag        string
	Org         string
	IsPrivate   bool
}

type Resolver struct {
	mu    sync.RWMutex
	cache map[string]Location
	cidrs []cidrEntry
}

type cidrEntry struct {
	ipNet *net.IPNet
	loc   Location
}

var (
	defaultResolver *Resolver
	once            sync.Once
)

func CountryCodeToFlag(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 {
		if cc == "LAN" {
			return "🏠"
		}
		return "🌐"
	}
	r1 := rune(0x1F1E6 + int(cc[0]-'A'))
	r2 := rune(0x1F1E6 + int(cc[1]-'A'))
	return string([]rune{r1, r2})
}

func GetResolver() *Resolver {
	once.Do(func() {
		defaultResolver = NewResolver()
	})
	return defaultResolver
}

func Lookup(ipStr string) Location {
	return GetResolver().Lookup(ipStr)
}

func NewResolver() *Resolver {
	r := &Resolver{
		cache: make(map[string]Location),
		cidrs: make([]cidrEntry, 0, 64),
	}
	r.initBuiltinCIDRs()
	return r
}

func (r *Resolver) addCIDR(cidrStr, cc, name, org string) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err == nil {
		r.cidrs = append(r.cidrs, cidrEntry{
			ipNet: ipNet,
			loc: Location{
				CountryCode: cc,
				CountryName: name,
				Flag:        CountryCodeToFlag(cc),
				Org:         org,
				IsPrivate:   false,
			},
		})
	}
}

func (r *Resolver) initBuiltinCIDRs() {
	// Anycast & Major DNS Providers
	r.addCIDR("8.8.8.0/24", "US", "United States", "Google Public DNS")
	r.addCIDR("8.8.4.0/24", "US", "United States", "Google Public DNS")
	r.addCIDR("1.1.1.0/24", "US", "United States", "Cloudflare DNS")
	r.addCIDR("1.0.0.0/24", "US", "United States", "Cloudflare DNS")
	r.addCIDR("9.9.9.0/24", "US", "United States", "Quad9 DNS")
	r.addCIDR("208.67.222.0/24", "US", "United States", "Cisco OpenDNS")
	r.addCIDR("208.67.220.0/24", "US", "United States", "Cisco OpenDNS")

	// Major Global Cloud & CDN Ranges
	r.addCIDR("142.250.0.0/16", "US", "United States", "Google LLC")
	r.addCIDR("172.217.0.0/16", "US", "United States", "Google LLC")
	r.addCIDR("93.184.216.0/24", "US", "United States", "Edgecast / Verizon Digital Media")
	r.addCIDR("104.16.0.0/12", "US", "United States", "Cloudflare CDN")
	r.addCIDR("13.107.0.0/16", "US", "United States", "Microsoft Azure")
	r.addCIDR("52.0.0.0/11", "US", "United States", "Amazon AWS")
	r.addCIDR("18.0.0.0/11", "US", "United States", "Amazon AWS")
	r.addCIDR("140.82.112.0/20", "US", "United States", "GitHub Inc.")

	// European Ranges
	r.addCIDR("185.220.101.0/24", "DE", "Germany", "Tor Exit Node / Scanner")
	r.addCIDR("185.220.100.0/22", "DE", "Germany", "Tor Project / Privacy Proxy")
	r.addCIDR("88.198.0.0/16", "DE", "Germany", "Hetzner Online GmbH")
	r.addCIDR("136.243.0.0/16", "DE", "Germany", "Hetzner Online GmbH")
	r.addCIDR("51.254.0.0/16", "FR", "France", "OVH SAS")
	r.addCIDR("178.32.0.0/15", "FR", "France", "OVH SAS")
	r.addCIDR("185.86.148.0/22", "GB", "United Kingdom", "M247 Ltd")

	// Asian Ranges
	r.addCIDR("103.21.244.0/22", "IN", "India", "Cloudflare India")
	r.addCIDR("14.139.0.0/16", "IN", "India", "National Knowledge Network India")
	r.addCIDR("103.27.0.0/16", "IN", "India", "Reliance Jio Infocomm")
	r.addCIDR("157.32.0.0/11", "IN", "India", "Bharti Airtel Ltd")
	r.addCIDR("125.16.0.0/12", "IN", "India", "Bharti Airtel Ltd")
	r.addCIDR("118.238.0.0/16", "JP", "Japan", "NTT Communications")
	r.addCIDR("220.100.0.0/16", "JP", "Japan", "KDDI Corporation")
	r.addCIDR("180.76.0.0/16", "CN", "China", "Baidu Spider")
	r.addCIDR("220.181.0.0/16", "CN", "China", "China Telecom")

	// Special / Documentation / Threat Feeds
	r.addCIDR("198.51.100.0/24", "US", "United States", "Threat Intelligence / Test Range")
	r.addCIDR("203.0.113.0/24", "US", "United States", "Threat Intelligence / Test Range")
}

func (r *Resolver) Lookup(ipStr string) Location {
	if ipStr == "" || ipStr == "unknown" {
		return Location{CountryCode: "??", CountryName: "Unknown", Flag: "🌐", Org: "Unknown", IsPrivate: false}
	}

	r.mu.RLock()
	if loc, ok := r.cache[ipStr]; ok {
		r.mu.RUnlock()
		return loc
	}
	r.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Location{CountryCode: "??", CountryName: "Unknown", Flag: "🌐", Org: "Malformed IP", IsPrivate: false}
	}

	var loc Location

	// Check Private / LAN / Loopback
	if ip.IsLoopback() {
		loc = Location{CountryCode: "LAN", CountryName: "Loopback Interface", Flag: "🏠", Org: "Localhost", IsPrivate: true}
	} else if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		loc = Location{CountryCode: "LAN", CountryName: "Local Area Network", Flag: "🏠", Org: "Internal Network (RFC1918)", IsPrivate: true}
	} else if ip.IsMulticast() {
		loc = Location{CountryCode: "MCAST", CountryName: "Multicast Group", Flag: "📡", Org: "Multicast Network", IsPrivate: true}
	} else {
		// Check CIDRs
		found := false
		for _, entry := range r.cidrs {
			if entry.ipNet.Contains(ip) {
				loc = entry.loc
				found = true
				break
			}
		}

		if !found {
			// Default fallback for unresolved public IPs
			loc = Location{
				CountryCode: "WAN",
				CountryName: "Public Internet",
				Flag:        "🌐",
				Org:         "External Host",
				IsPrivate:   false,
			}
		}
	}

	r.mu.Lock()
	r.cache[ipStr] = loc
	r.mu.Unlock()

	return loc
}
