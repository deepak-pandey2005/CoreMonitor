package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/engine"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/geoip"
)

// UI Theme Styles
var (
	subtleColor    = lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#383838"}
	highlightColor = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	specialColor   = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	warnColor      = lipgloss.AdaptiveColor{Light: "#FFA500", Dark: "#FFAE34"}
	critColor      = lipgloss.AdaptiveColor{Light: "#FF0000", Dark: "#FF4D4D"}

	docStyle = lipgloss.NewStyle().Margin(1, 2)

	tabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Foreground(lipgloss.Color("#888888"))

	activeTabStyle = tabStyle.
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(highlightColor)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(subtleColor).
			Padding(0, 1)

	headerTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#00FFFF"))

	statusLive = lipgloss.NewStyle().
			Bold(true).
			Foreground(specialColor)

	statusPaused = lipgloss.NewStyle().
			Bold(true).
			Foreground(warnColor)

	critBadge = lipgloss.NewStyle().
			Bold(true).
			Background(critColor).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1)

	highBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(critColor)

	medBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(warnColor)
)

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type Model struct {
	engine        *engine.Engine
	iface         string
	activeTab     int // 0: Overview, 1: Packets, 2: Alerts
	paused        bool
	cachedStats   engine.Stats
	packetCursor  int
	alertCursor   int
	flowCursor    int
	showDetail    bool
	detailContent string
	filtering     bool
	filterInput   string
	filterError   string
	activeFilter  string
	width         int
	height        int
}

func NewModel(eng *engine.Engine, iface string) Model {
	activeBPF := ""
	if eng != nil {
		activeBPF = eng.GetBPFFilter()
	}
	return Model{
		engine:       eng,
		iface:        iface,
		activeTab:    0,
		paused:       false,
		cachedStats:  eng.GetStats(),
		activeFilter: activeBPF,
		width:        100,
		height:       30,
	}
}

func (m Model) Init() tea.Cmd {
	return tickCmd()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.showDetail {
			if msg.String() == "esc" || msg.String() == "enter" || msg.String() == "q" {
				m.showDetail = false
				return m, nil
			}
		}

		if m.filtering {
			switch msg.String() {
			case "esc":
				m.filtering = false
				m.filterError = ""
				return m, nil
			case "enter":
				apply := strings.TrimSpace(m.filterInput)
				if strings.EqualFold(apply, "clear") || strings.EqualFold(apply, "none") {
					apply = ""
				}
				err := m.engine.SetBPFFilter(apply)
				if err != nil {
					m.filterError = err.Error()
					return m, nil
				}
				m.activeFilter = apply
				m.filtering = false
				m.filterError = ""
				return m, nil
			case "backspace":
				if len(m.filterInput) > 0 {
					m.filterInput = m.filterInput[:len(m.filterInput)-1]
				}
				return m, nil
			case "ctrl+u":
				m.filterInput = ""
				return m, nil
			default:
				if len(msg.String()) == 1 {
					m.filterInput += msg.String()
				}
				return m, nil
			}
		}

		switch msg.String() {
		case "ctrl+c", "q":
			m.engine.Stop()
			return m, tea.Quit

		case "/":
			m.filtering = true
			m.filterInput = m.activeFilter
			m.filterError = ""
			return m, nil

		case "tab":
			m.activeTab = (m.activeTab + 1) % 5

		case "shift+tab":
			m.activeTab = (m.activeTab + 4) % 5

		case "1":
			m.activeTab = 0
		case "2":
			m.activeTab = 1
		case "3":
			m.activeTab = 2
		case "4":
			m.activeTab = 3
		case "5":
			m.activeTab = 4

		case " ":
			m.paused = !m.paused

		case "up", "k":
			if m.activeTab == 1 && m.packetCursor > 0 {
				m.packetCursor--
			} else if m.activeTab == 2 && m.alertCursor > 0 {
				m.alertCursor--
			} else if m.activeTab == 4 && m.flowCursor > 0 {
				m.flowCursor--
			}

		case "down", "j":
			if m.activeTab == 1 && m.packetCursor < len(m.cachedStats.RecentPackets)-1 {
				m.packetCursor++
			} else if m.activeTab == 2 && m.alertCursor < len(m.cachedStats.RecentAlerts)-1 {
				m.alertCursor++
			} else if m.activeTab == 4 && m.flowCursor < len(m.cachedStats.ActiveFlows)-1 {
				m.flowCursor++
			}

		case "enter":
			if m.activeTab == 1 && len(m.cachedStats.RecentPackets) > 0 {
				idx := len(m.cachedStats.RecentPackets) - 1 - m.packetCursor
				if idx >= 0 && idx < len(m.cachedStats.RecentPackets) {
					p := m.cachedStats.RecentPackets[idx]
					httpInfo := ""
					if p.HTTPMethod != "" {
						httpInfo = fmt.Sprintf("\nHTTP:        %s %s%s (UA: %s)", p.HTTPMethod, p.HTTPHost, p.HTTPURI, p.HTTPUserAgent)
					}
					m.detailContent = fmt.Sprintf("PACKET DETAILS:\n\nTimestamp:   %s\nSource:      %s %s:%d (%s - %s)\nDestination: %s %s:%d (%s - %s)\nProtocol:    %s\nService:     %s\nSize:        %d bytes\nPayload:     %d bytes\nTCP Flags:   %s\nTLS SNI:     %s%s\nDNS Query:   %s\nSrc MAC:     %s\nDst MAC:     %s\nBroadcast:   %t\n\n(Press ESC or Enter to close)",
						p.Timestamp.Format(time.RFC3339Nano), p.SrcFlag, p.SrcIP, p.SrcPort, p.SrcCountry, p.SrcOrg,
						p.DstFlag, p.DstIP, p.DstPort, p.DstCountry, p.DstOrg,
						p.Protocol, p.Service, p.PacketSize, p.PayloadSize, p.TCPFlagsStr, p.TLSSNI, httpInfo, p.DNSQuery, p.SrcMAC, p.DstMAC, p.IsBroadcast)
					m.showDetail = true
				}
			} else if m.activeTab == 2 && len(m.cachedStats.RecentAlerts) > 0 {
				idx := len(m.cachedStats.RecentAlerts) - 1 - m.alertCursor
				if idx >= 0 && idx < len(m.cachedStats.RecentAlerts) {
					a := m.cachedStats.RecentAlerts[idx]
					m.detailContent = fmt.Sprintf("SECURITY ALERT DETAILS:\n\nSeverity:    %s\nAlert Type:  %s\nTimestamp:   %s\nSource:      %s %s:%d (%s)\nTarget:      %s %s:%d (%s)\nProtocol:    %s\nMessage:     %s\nDetails:     %s\n\n(Press ESC or Enter to close)",
						a.Severity, a.AlertType, a.Timestamp.Format(time.RFC3339Nano),
						a.SrcFlag, a.SrcIP, a.SrcPort, a.SrcCountry,
						a.DstFlag, a.DstIP, a.DstPort, a.DstCountry,
						a.Protocol, a.Message, a.Details)
					m.showDetail = true
				}
			} else if m.activeTab == 4 && len(m.cachedStats.ActiveFlows) > 0 {
				idx := m.flowCursor
				if idx >= 0 && idx < len(m.cachedStats.ActiveFlows) {
					f := m.cachedStats.ActiveFlows[idx]
					appMeta := ""
					if f.TLSSNI != "" {
						appMeta = fmt.Sprintf("\nTLS SNI:     %s", f.TLSSNI)
					} else if f.HTTPMethod != "" {
						appMeta = fmt.Sprintf("\nHTTP:        %s %s%s", f.HTTPMethod, f.HTTPHost, f.HTTPURI)
					} else if f.DNSQuery != "" {
						appMeta = fmt.Sprintf("\nDNS Query:   %s", f.DNSQuery)
					}
					m.detailContent = fmt.Sprintf("5-TUPLE FLOW CONVERSATION:\n\nProtocol:    %s\nService:     %s\nState:       %s\nDuration:    %s\n\nInitiator:   %s %s:%d\n  Packets:   %d\n  Volume:    %d bytes\n\nResponder:   %s %s:%d\n  Packets:   %d\n  Volume:    %d bytes\n\nTotals:\n  Packets:   %d\n  Volume:    %d bytes%s\n\n(Press ESC or Enter to close)",
						f.Protocol, f.Service, f.State, f.Duration().Truncate(time.Millisecond),
						f.SrcFlag, f.InitiatorIP, f.InitiatorPort, f.PacketsInitiator, f.BytesInitiator,
						f.DstFlag, f.ResponderIP, f.ResponderPort, f.PacketsResponder, f.BytesResponder,
						f.TotalPackets, f.TotalBytes, appMeta)
					m.showDetail = true
				}
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		if !m.paused {
			m.cachedStats = m.engine.GetStats()
		}
		return m, tickCmd()
	}

	return m, nil
}

func (m Model) View() string {
	var b strings.Builder

	// Top Navigation Bar
	tabs := []string{
		"1: Overview",
		"2: Live Packets",
		fmt.Sprintf("3: Alerts (%d)", len(m.cachedStats.RecentAlerts)),
		fmt.Sprintf("4: IPS Jails (%d)", len(m.cachedStats.BannedHosts)),
		fmt.Sprintf("5: Flows (%d)", m.cachedStats.FlowStats.ActiveFlows),
	}
	var renderedTabs []string
	for i, t := range tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, activeTabStyle.Render(t))
		} else {
			renderedTabs = append(renderedTabs, tabStyle.Render(t))
		}
	}

	status := statusLive.Render("● LIVE")
	if m.cachedStats.IsReplay {
		if m.cachedStats.ReplayFinished {
			status = lipgloss.NewStyle().Bold(true).Foreground(specialColor).Render("✔ REPLAY COMPLETE")
		} else if m.cachedStats.ReplaySpeed > 0 {
			status = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(fmt.Sprintf("▶ REPLAY (%.1fx)", m.cachedStats.ReplaySpeed))
		} else {
			status = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render("▶ REPLAY (MAX)")
		}
	}
	if m.paused {
		status = statusPaused.Render("⏸ PAUSED")
	}

	uptime := time.Since(m.cachedStats.StartTime).Truncate(time.Second)

	filterBadge := lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("BPF: [none]")
	if m.activeFilter != "" {
		filterBadge = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(fmt.Sprintf("BPF: [%s]", m.activeFilter))
	}

	rightWidth := m.width - 60
	if rightWidth < 20 {
		rightWidth = 20
	}

	navRow := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...),
		lipgloss.NewStyle().Width(rightWidth).Align(lipgloss.Right).Render(
			fmt.Sprintf("%s  |  Iface: %s  |  Uptime: %s  |  %s", filterBadge, m.iface, uptime, status),
		),
	)
	b.WriteString(navRow + "\n\n")

	// Render Selected Tab Content
	switch m.activeTab {
	case 0:
		b.WriteString(m.renderOverview())
	case 1:
		b.WriteString(m.renderPackets())
	case 2:
		b.WriteString(m.renderAlerts())
	case 3:
		b.WriteString(m.renderIPS())
	case 4:
		b.WriteString(m.renderFlows())
	}

	// Dynamic BPF Filter prompt overlay
	if m.filtering {
		promptStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#00FFFF")).
			Background(lipgloss.Color("#16213e")).
			Padding(0, 1).
			MarginTop(1)

		promptText := fmt.Sprintf("🔍 BPF Filter (live pcap) > %s█\n(Enter: apply, ESC: cancel, type 'clear' to reset)", m.filterInput)
		if m.filterError != "" {
			errText := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render("\n❌ " + m.filterError)
			promptText += errText
		}
		b.WriteString("\n" + promptStyle.Render(promptText))
	}

	// Modal detail overlay
	if m.showDetail {
		modal := lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(highlightColor).
			Background(lipgloss.Color("#1a1a2e")).
			Padding(1, 2).
			Width(65).
			Render(m.detailContent)
		return modal
	}

	// Footer Help
	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#666666")).
		MarginTop(1).
		Render("  [/] Set BPF Filter  •  [Tab/1-5] Switch View  •  [Space] Pause/Resume  •  [↑/↓] Select  •  [Enter] Inspect  •  [q] Quit")
	b.WriteString(footer)

	return docStyle.Render(b.String())
}

func (m Model) renderOverview() string {
	stats := m.cachedStats

	// Flow Box
	totalMB := float64(stats.TotalBytes) / (1024 * 1024)
	rateKBs := stats.BytesPerSec / 1024
	siemInfo := ""
	if stats.SIEMStats.EventsSent > 0 {
		siemInfo = fmt.Sprintf("\nSIEM Events:   %s", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(fmt.Sprintf("%d sent", stats.SIEMStats.EventsSent)))
	}
	flowContent := fmt.Sprintf(
		"Total Packets: %s\nTotal Volume:  %.2f MB\nThroughput:    %s\nPacket Rate:   %.1f pkts/s%s",
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(fmt.Sprintf("%d", stats.TotalPackets)),
		totalMB,
		lipgloss.NewStyle().Bold(true).Foreground(specialColor).Render(fmt.Sprintf("%.2f KB/s", rateKBs)),
		stats.PktsPerSec,
		siemInfo,
	)

	// Protocols Box
	type pPair struct {
		name  string
		count uint64
	}
	var protos []pPair
	for k, v := range stats.ProtocolCounts {
		protos = append(protos, pPair{k, v})
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i].count > protos[j].count })

	var protoLines []string
	for i := 0; i < 4 && i < len(protos); i++ {
		pct := float64(0)
		if stats.TotalPackets > 0 {
			pct = (float64(protos[i].count) / float64(stats.TotalPackets)) * 100
		}
		protoLines = append(protoLines, fmt.Sprintf("%-6s %-7d (%4.1f%%)", protos[i].name, protos[i].count, pct))
	}
	if len(protoLines) == 0 {
		protoLines = append(protoLines, "Listening for traffic...")
	}

	// Top Talkers Box
	type tPair struct {
		ip    string
		bytes uint64
	}
	var talkers []tPair
	for k, v := range stats.TopTalkersBytes {
		talkers = append(talkers, tPair{k, v})
	}
	sort.Slice(talkers, func(i, j int) bool { return talkers[i].bytes > talkers[j].bytes })

	var talkerLines []string
	for i := 0; i < 4 && i < len(talkers); i++ {
		loc := geoip.Lookup(talkers[i].ip)
		vol := fmt.Sprintf("%.1f KB", float64(talkers[i].bytes)/1024)
		if talkers[i].bytes > 1024*1024 {
			vol = fmt.Sprintf("%.2f MB", float64(talkers[i].bytes)/(1024*1024))
		}
		talkerLines = append(talkerLines, fmt.Sprintf("%s %-15s %s", loc.Flag, talkers[i].ip, vol))
	}
	if len(talkerLines) == 0 {
		talkerLines = append(talkerLines, "Waiting for traffic...")
	}

	// Responsive box sizing and layout
	availWidth := m.width - 4
	if availWidth < 30 {
		availWidth = 80
	}
	alertsWidth := availWidth
	if alertsWidth > 102 {
		alertsWidth = 102
	}

	var flowBox, protoBox, talkerBox string
	var topRow string

	if m.width > 0 && m.width < 90 {
		flowBox = boxStyle.Width(alertsWidth).Render(headerTitleStyle.Render("FLOW METRICS\n") + flowContent)
		protoBox = boxStyle.Width(alertsWidth).Render(headerTitleStyle.Render("PROTOCOLS\n") + strings.Join(protoLines, "\n"))
		talkerBox = boxStyle.Width(alertsWidth).Render(headerTitleStyle.Render("TOP TALKERS\n") + strings.Join(talkerLines, "\n"))
		topRow = lipgloss.JoinVertical(lipgloss.Left, flowBox, protoBox, talkerBox)
	} else {
		flowBox = boxStyle.Width(35).Render(headerTitleStyle.Render("FLOW METRICS\n") + flowContent)
		protoBox = boxStyle.Width(30).Render(headerTitleStyle.Render("PROTOCOLS\n") + strings.Join(protoLines, "\n"))
		talkerBox = boxStyle.Width(32).Render(headerTitleStyle.Render("TOP TALKERS\n") + strings.Join(talkerLines, "\n"))
		topRow = lipgloss.JoinHorizontal(lipgloss.Top, flowBox, " ", protoBox, " ", talkerBox)
	}

	// Alerts Ticker Row
	var alertLines []string
	if len(stats.RecentAlerts) == 0 {
		alertLines = append(alertLines, lipgloss.NewStyle().Foreground(specialColor).Render("✓ Network baseline normal. No active threats detected."))
	} else {
		start := 0
		if len(stats.RecentAlerts) > 4 {
			start = len(stats.RecentAlerts) - 4
		}
		for i := len(stats.RecentAlerts) - 1; i >= start; i-- {
			a := stats.RecentAlerts[i]
			badge := medBadge.Render("[MED]")
			if a.Severity == "CRITICAL" {
				badge = critBadge.Render("CRITICAL")
			} else if a.Severity == "HIGH" {
				badge = highBadge.Render("[HIGH]")
			}
			tStr := a.Timestamp.Format("15:04:05")
			alertLines = append(alertLines, fmt.Sprintf(" %s %s %-16s %s -> %s | %s",
				tStr, badge, a.AlertType, a.SrcIP, a.DstIP, a.Message))
		}
	}
	alertsBox := boxStyle.Width(alertsWidth).Render(lipgloss.NewStyle().Bold(true).Foreground(critColor).Render("RECENT SECURITY ALERTS\n") + strings.Join(alertLines, "\n"))

	return lipgloss.JoinVertical(lipgloss.Left, topRow, "\n", alertsBox)
}

func (m Model) renderPackets() string {
	packets := m.cachedStats.RecentPackets
	if len(packets) == 0 {
		return "  Listening for packets on " + m.iface + "..."
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("   %-10s  %-21s  %-21s  %-6s %-12s %-6s %s",
		"TIME", "SOURCE", "DESTINATION", "PROTO", "SERVICE", "SIZE", "INFO / FLAGS"))

	maxRows := 12
	startIdx := len(packets) - 1
	for i := 0; i < maxRows && (startIdx-i) >= 0; i++ {
		p := packets[startIdx-i]
		cursor := "  "
		rowStyle := lipgloss.NewStyle()
		if i == m.packetCursor {
			cursor = "> "
			rowStyle = rowStyle.Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#333366"))
		}

		tStr := p.Timestamp.Format("15:04:05")
		src := fmt.Sprintf("%s %s:%d", p.SrcFlag, p.SrcIP, p.SrcPort)
		if p.SrcPort == 0 {
			src = fmt.Sprintf("%s %s", p.SrcFlag, p.SrcIP)
		}
		dst := fmt.Sprintf("%s %s:%d", p.DstFlag, p.DstIP, p.DstPort)
		if p.DstPort == 0 {
			dst = fmt.Sprintf("%s %s", p.DstFlag, p.DstIP)
		}
		extra := p.TCPFlagsStr
		if p.TLSSNI != "" {
			extra = "🔒 " + p.TLSSNI
		} else if p.HTTPMethod != "" {
			uri := p.HTTPURI
			if len(uri) > 18 {
				uri = uri[:18] + "…"
			}
			host := p.HTTPHost
			if host != "" {
				extra = fmt.Sprintf("🌐 %s %s%s", p.HTTPMethod, host, uri)
			} else {
				extra = fmt.Sprintf("🌐 %s %s", p.HTTPMethod, uri)
			}
		} else if p.DNSQuery != "" {
			extra = "🌐 " + p.DNSQuery
		}
		row := fmt.Sprintf("%s%-10s  %-21s  %-21s  %-6s %-12s %-6dB %s",
			cursor, tStr, src, dst, p.Protocol, p.Service, p.PacketSize, extra)
		lines = append(lines, rowStyle.Render(row))
	}

	return strings.Join(lines, "\n")
}

func (m Model) renderAlerts() string {
	alerts := m.cachedStats.RecentAlerts
	if len(alerts) == 0 {
		return "  ✓ No security alerts detected."
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("   %-10s  %-10s  %-20s  %-35s  %s",
		"TIME", "SEVERITY", "ALERT TYPE", "SOURCE -> TARGET", "MESSAGE"))

	maxRows := 12
	startIdx := len(alerts) - 1
	for i := 0; i < maxRows && (startIdx-i) >= 0; i++ {
		a := alerts[startIdx-i]
		cursor := "  "
		rowStyle := lipgloss.NewStyle()
		if i == m.alertCursor {
			cursor = "> "
			rowStyle = rowStyle.Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#442222"))
		}

		sev := a.Severity
		tStr := a.Timestamp.Format("15:04:05")
		srcDst := fmt.Sprintf("%s %s -> %s %s", a.SrcFlag, a.SrcIP, a.DstFlag, a.DstIP)

		row := fmt.Sprintf("%s%-10s  %-10s  %-20s  %-35s  %s",
			cursor, tStr, sev, a.AlertType, srcDst, a.Message)
		lines = append(lines, rowStyle.Render(row))
	}

	return strings.Join(lines, "\n")
}

func (m Model) renderIPS() string {
	banned := m.cachedStats.BannedHosts
	if len(banned) == 0 {
		return "  🛡️ Active Defense (IPS): No hosts currently jailed/blocked. Network perimeter secure."
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("   %-16s  %-6s  %-12s  %-12s  %s",
		"BANNED IP", "GEO", "SEVERITY", "TIME LEFT", "TRIGGER REASON"))

	now := time.Now()
	for _, h := range banned {
		loc := geoip.Lookup(h.IP)
		timeLeft := h.ExpiresAt.Sub(now).Truncate(time.Second)
		if timeLeft < 0 {
			timeLeft = 0
		}

		sev := h.Severity
		if h.Severity == "CRITICAL" {
			sev = critBadge.Render("CRITICAL")
		} else if h.Severity == "HIGH" {
			sev = highBadge.Render("[HIGH]")
		}

		row := fmt.Sprintf("   %-16s  %s %-3s  %-12s  %-12s  %s",
			h.IP, loc.Flag, loc.CountryCode, sev, timeLeft, h.Reason)
		lines = append(lines, row)
	}

	return strings.Join(lines, "\n")
}

func (m Model) renderFlows() string {
	flows := m.cachedStats.ActiveFlows
	if len(flows) == 0 {
		return "  No active conversation flows tracked. Listening on " + m.iface + "..."
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("   %-24s  %-24s  %-6s %-8s %-12s %-10s %-8s %s",
		"INITIATOR", "RESPONDER", "PROTO", "SERVICE", "PKTS (F/R)", "VOLUME", "DURATION", "STATE / DETAILS"))

	maxRows := 12
	for i := 0; i < maxRows && i < len(flows); i++ {
		f := flows[i]
		cursor := "  "
		rowStyle := lipgloss.NewStyle()
		if i == m.flowCursor {
			cursor = "> "
			rowStyle = rowStyle.Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#2d3748"))
		}

		initEp := fmt.Sprintf("%s %s:%d", f.SrcFlag, f.InitiatorIP, f.InitiatorPort)
		respEp := fmt.Sprintf("%s %s:%d", f.DstFlag, f.ResponderIP, f.ResponderPort)
		pkts := fmt.Sprintf("%d / %d", f.PacketsInitiator, f.PacketsResponder)
		vol := fmt.Sprintf("%.1f KB", float64(f.TotalBytes)/1024)
		if f.TotalBytes < 1024 {
			vol = fmt.Sprintf("%d B", f.TotalBytes)
		}
		dur := f.Duration().Truncate(time.Millisecond).String()

		detail := f.State
		if f.TLSSNI != "" {
			detail += " 🔒 " + f.TLSSNI
		} else if f.HTTPMethod != "" {
			detail += " 🌐 " + f.HTTPMethod + " " + f.HTTPHost
		} else if f.DNSQuery != "" {
			detail += " 🌐 " + f.DNSQuery
		}

		row := fmt.Sprintf("%s%-24s  %-24s  %-6s %-8s %-12s %-10s %-8s %s",
			cursor, initEp, respEp, f.Protocol, f.Service, pkts, vol, dur, detail)
		lines = append(lines, rowStyle.Render(row))
	}

	return strings.Join(lines, "\n")
}

// RunBubbleTea starts the interactive TUI
func RunBubbleTea(eng *engine.Engine, iface string) error {
	m := NewModel(eng, iface)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
