package tui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/engine"
)

// ANSI color escape codes
const (
	Reset       = "\033[0m"
	Bold        = "\033[1m"
	Dim         = "\033[2m"
	Red         = "\033[31m"
	Green       = "\033[32m"
	Yellow      = "\033[33m"
	Blue        = "\033[34m"
	Magenta     = "\033[35m"
	Cyan        = "\033[36m"
	White       = "\033[37m"
	BgRed       = "\033[41m"
	ClearScreen = "\033[H\033[2J"
)

func Render(iface string, stats engine.Stats) {
	var b strings.Builder
	b.WriteString(ClearScreen)

	uptime := time.Since(stats.StartTime).Truncate(time.Second)

	// Header
	b.WriteString(fmt.Sprintf("%s%s┌────────────────────────────────────────────────────────────────────────────────────────┐%s\n", Bold, Blue, Reset))
	b.WriteString(fmt.Sprintf("%s%s│  Interface: %s%-10s%s  🛡️  CoreMonitor Network IDS (C Core + Go)  Uptime: %s%-12s%s│%s\n",
		Bold, Blue, Yellow, iface, Bold+Blue, White, uptime, Bold+Blue, Reset))
	b.WriteString(fmt.Sprintf("%s%s└────────────────────────────────────────────────────────────────────────────────────────┘%s\n", Bold, Blue, Reset))

	// Bandwidth Metrics
	totalMB := float64(stats.TotalBytes) / (1024 * 1024)
	rateKBs := stats.BytesPerSec / 1024
	b.WriteString(fmt.Sprintf("%s%s[ FLOW METRICS ]%s\n", Bold, Cyan, Reset))
	b.WriteString(fmt.Sprintf("  • Total Packets: %s%-12d%s  • Volume:     %s%-10.2f MB%s\n",
		Bold+White, stats.TotalPackets, Reset, Bold+White, totalMB, Reset))
	b.WriteString(fmt.Sprintf("  • Throughput:    %s%-10.2f KB/s%s  • Packet Rate: %s%-10.1f pkts/s%s\n\n",
		Bold+Green, rateKBs, Reset, Bold+Green, stats.PktsPerSec, Reset))

	// Protocols & Top Talkers
	b.WriteString(fmt.Sprintf("%s%s[ PROTOCOLS ]%s                                    %s%s[ TOP TALKERS ]%s\n",
		Bold, Magenta, Reset, Bold, Yellow, Reset))

	type protoPair struct {
		name  string
		count uint64
	}
	var protos []protoPair
	for k, v := range stats.ProtocolCounts {
		protos = append(protos, protoPair{name: k, count: v})
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i].count > protos[j].count })

	type talkerPair struct {
		ip    string
		bytes uint64
	}
	var talkers []talkerPair
	for k, v := range stats.TopTalkersBytes {
		talkers = append(talkers, talkerPair{ip: k, bytes: v})
	}
	sort.Slice(talkers, func(i, j int) bool { return talkers[i].bytes > talkers[j].bytes })

	maxRows := 4
	for i := 0; i < maxRows; i++ {
		pStr := "  - "
		if i < len(protos) {
			pct := float64(0)
			if stats.TotalPackets > 0 {
				pct = (float64(protos[i].count) / float64(stats.TotalPackets)) * 100
			}
			pStr = fmt.Sprintf("  %-8s %-8d (%4.1f%%)", protos[i].name, protos[i].count, pct)
		}

		tStr := ""
		if i < len(talkers) {
			vol := fmt.Sprintf("%.1f KB", float64(talkers[i].bytes)/1024)
			if talkers[i].bytes > 1024*1024 {
				vol = fmt.Sprintf("%.2f MB", float64(talkers[i].bytes)/(1024*1024))
			}
			tStr = fmt.Sprintf("%-18s %s", talkers[i].ip, vol)
		}
		b.WriteString(fmt.Sprintf("%-45s  %s\n", pStr, tStr))
	}
	b.WriteString("\n")

	// IDS Alerts Panel
	b.WriteString(fmt.Sprintf("%s%s🚨 [ LIVE IDS SECURITY ALERTS ]%s\n", Bold, Red, Reset))
	if len(stats.RecentAlerts) == 0 {
		b.WriteString(fmt.Sprintf("  %s✓ Network baseline normal. No threats detected.%s\n", Green, Reset))
	} else {
		start := 0
		if len(stats.RecentAlerts) > 5 {
			start = len(stats.RecentAlerts) - 5
		}
		for i := len(stats.RecentAlerts) - 1; i >= start; i-- {
			a := stats.RecentAlerts[i]
			sevBadge := fmt.Sprintf("[%s]", a.Severity)
			if a.Severity == "CRITICAL" {
				sevBadge = fmt.Sprintf("%s%s CRITICAL %s", Bold+White, BgRed, Reset)
			} else if a.Severity == "HIGH" {
				sevBadge = fmt.Sprintf("%s%s HIGH %s", Bold, Red, Reset)
			} else {
				sevBadge = fmt.Sprintf("%s%s MEDIUM %s", Bold, Yellow, Reset)
			}
			tStr := a.Timestamp.Format("15:04:05")
			b.WriteString(fmt.Sprintf("  %s %s %-18s %s -> %s\n    └─ %s\n",
				Dim+tStr+Reset, sevBadge, a.AlertType, a.SrcIP, a.DstIP, a.Message))
		}
	}
	b.WriteString("\n")

	// Recent Packets Log
	b.WriteString(fmt.Sprintf("%s%s[ RECENT PACKETS ]%s\n", Bold, White, Reset))
	pStart := 0
	if len(stats.RecentPackets) > 5 {
		pStart = len(stats.RecentPackets) - 5
	}
	for i := len(stats.RecentPackets) - 1; i >= pStart; i-- {
		p := stats.RecentPackets[i]
		tStr := p.Timestamp.Format("15:04:05")
		src := fmt.Sprintf("%s:%d", p.SrcIP, p.SrcPort)
		if p.SrcPort == 0 {
			src = p.SrcIP
		}
		dst := fmt.Sprintf("%s:%d", p.DstIP, p.DstPort)
		if p.DstPort == 0 {
			dst = p.DstIP
		}
		extra := p.TCPFlagsStr
		if p.DNSQuery != "" {
			extra = p.DNSQuery
		}
		b.WriteString(fmt.Sprintf("  %s  %-21s -> %-21s  %-5s %-12s %4dB  %s\n",
			Dim+tStr+Reset, src, dst, p.Protocol, p.Service, p.PacketSize, extra))
	}

	_, _ = os.Stdout.WriteString(b.String())
}
