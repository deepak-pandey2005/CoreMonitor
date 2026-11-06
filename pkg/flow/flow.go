package flow

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
)

// FlowKey represents a canonical 5-tuple identifying a bidirectional conversation.
type FlowKey struct {
	Protocol string
	IP1      string
	Port1    uint16
	IP2      string
	Port2    uint16
}

// MakeCanonicalKey ensures packets from A->B and B->A map to the same FlowKey.
func MakeCanonicalKey(proto, srcIP, dstIP string, srcPort, dstPort uint16) (FlowKey, bool) {
	// A packet is "forward" (originating from initiator) if src matches (IP1, Port1).
	cmp := strings.Compare(srcIP, dstIP)
	if cmp < 0 || (cmp == 0 && srcPort <= dstPort) {
		return FlowKey{
			Protocol: proto,
			IP1:      srcIP,
			Port1:    srcPort,
			IP2:      dstIP,
			Port2:    dstPort,
		}, true
	}
	return FlowKey{
		Protocol: proto,
		IP1:      dstIP,
		Port1:    dstPort,
		IP2:      srcIP,
		Port2:    srcPort,
	}, false
}

// Flow aggregates bidirectional metrics for a single 5-tuple conversation.
type Flow struct {
	Key FlowKey

	InitiatorIP   string
	InitiatorPort uint16
	ResponderIP   string
	ResponderPort uint16
	Protocol      string
	Service       string

	StartTime time.Time
	LastSeen  time.Time

	PacketsInitiator uint64
	BytesInitiator   uint64
	PacketsResponder uint64
	BytesResponder   uint64

	TotalPackets uint64
	TotalBytes   uint64

	TCPFlags     uint8
	FinInitiator bool
	FinResponder bool
	State        string // "ACTIVE", "CLOSING", "CLOSED", "TIMED_OUT"

	TLSSNI     string
	HTTPMethod string
	HTTPHost   string
	HTTPURI    string
	DNSQuery   string

	SrcCountry string
	SrcFlag    string
	DstCountry string
	DstFlag    string
}

// Duration returns the active lifespan of the flow.
func (f *Flow) Duration() time.Duration {
	d := f.LastSeen.Sub(f.StartTime)
	if d < 0 {
		return 0
	}
	return d
}

// FlowStats provides snapshot counts of the flow aggregator.
type FlowStats struct {
	TotalFlowsCreated uint64
	ActiveFlows       int
	ClosedFlows       int
	TotalVolumeBytes  uint64
}

const DefaultMaxActiveFlows = 50000

// Manager orchestrates concurrent flow ingestion, aggregation, and expiration.
type Manager struct {
	mu            sync.RWMutex
	flows         map[FlowKey]*Flow
	closedHistory []*Flow
	totalCreated  uint64
	totalBytes    uint64

	idleTimeout   time.Duration
	activeTimeout time.Duration
	maxFlows      int
	lastPktTime   time.Time
	stopChan      chan struct{}
}

// NewManager creates a flow manager and runs a background janitor.
func NewManager(idleTimeout, activeTimeout time.Duration) *Manager {
	return NewManagerWithCapacity(idleTimeout, activeTimeout, DefaultMaxActiveFlows)
}

// NewManagerWithCapacity creates a flow manager with a configured maximum active flow capacity.
func NewManagerWithCapacity(idleTimeout, activeTimeout time.Duration, maxFlows int) *Manager {
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	if activeTimeout <= 0 {
		activeTimeout = 120 * time.Second
	}
	if maxFlows <= 0 {
		maxFlows = DefaultMaxActiveFlows
	}

	mgr := &Manager{
		flows:         make(map[FlowKey]*Flow),
		closedHistory: make([]*Flow, 0, 100),
		idleTimeout:   idleTimeout,
		activeTimeout: activeTimeout,
		maxFlows:      maxFlows,
		stopChan:      make(chan struct{}),
	}

	go mgr.janitorLoop()
	return mgr
}

// Ingest updates an existing flow or initializes a new flow from packet metadata.
func (m *Manager) Ingest(meta *cbridge.PacketMeta) *Flow {
	if meta == nil || meta.SrcIP == "" || meta.DstIP == "" {
		return nil
	}

	key, isInitiator := MakeCanonicalKey(meta.Protocol, meta.SrcIP, meta.DstIP, meta.SrcPort, meta.DstPort)

	m.mu.Lock()
	defer m.mu.Unlock()

	if !meta.Timestamp.IsZero() && meta.Timestamp.After(m.lastPktTime) {
		m.lastPktTime = meta.Timestamp
	}

	f, exists := m.flows[key]
	pktBytes := uint64(meta.PacketSize)

	if !exists {
		if len(m.flows) >= m.maxFlows {
			m.evictStaleFlowsLocked(meta.Timestamp)
			if len(m.flows) >= m.maxFlows {
				m.evictOldestLocked()
			}
		}

		f = &Flow{
			Key:           key,
			InitiatorIP:   meta.SrcIP,
			InitiatorPort: meta.SrcPort,
			ResponderIP:   meta.DstIP,
			ResponderPort: meta.DstPort,
			Protocol:      meta.Protocol,
			Service:       meta.Service,
			StartTime:     meta.Timestamp,
			LastSeen:      meta.Timestamp,
			State:         "ACTIVE",
			SrcCountry:    meta.SrcCountry,
			SrcFlag:       meta.SrcFlag,
			DstCountry:    meta.DstCountry,
			DstFlag:       meta.DstFlag,
		}
		m.flows[key] = f
		m.totalCreated++
	}

	f.LastSeen = meta.Timestamp
	f.TotalPackets++
	f.TotalBytes += pktBytes
	m.totalBytes += pktBytes

	if meta.SrcIP == f.InitiatorIP && meta.SrcPort == f.InitiatorPort {
		f.PacketsInitiator++
		f.BytesInitiator += pktBytes
	} else {
		f.PacketsResponder++
		f.BytesResponder += pktBytes
	}

	if f.Service == "" && meta.Service != "" {
		f.Service = meta.Service
	}
	if meta.TLSSNI != "" {
		f.TLSSNI = meta.TLSSNI
	}
	if meta.HTTPMethod != "" {
		f.HTTPMethod = meta.HTTPMethod
		f.HTTPHost = meta.HTTPHost
		f.HTTPURI = meta.HTTPURI
	}
	if meta.DNSQuery != "" {
		f.DNSQuery = meta.DNSQuery
	}

	f.TCPFlags |= meta.TCPFlags

	isFromInitiator := (meta.SrcIP == f.InitiatorIP && meta.SrcPort == f.InitiatorPort)
	if meta.TCPFlags&0x04 != 0 {
		// TCP RST immediately terminates connection
		f.State = "CLOSED"
	} else if meta.TCPFlags&0x01 != 0 {
		// TCP FIN received
		if isFromInitiator {
			f.FinInitiator = true
		} else {
			f.FinResponder = true
		}

		if f.FinInitiator && f.FinResponder {
			f.State = "CLOSED"
		} else {
			f.State = "CLOSING"
		}
	}

	_ = isInitiator
	return f
}

// GetActiveFlows returns a snapshot slice of all currently active flows.
func (m *Manager) GetActiveFlows() []*Flow {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Flow, 0, len(m.flows))
	for _, f := range m.flows {
		cp := *f
		result = append(result, &cp)
	}
	return result
}

// GetClosedFlows returns a snapshot slice of historically closed and timed out flows.
func (m *Manager) GetClosedFlows() []*Flow {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Flow, 0, len(m.closedHistory))
	for _, f := range m.closedHistory {
		cp := *f
		result = append(result, &cp)
	}
	return result
}

// GetTopFlows returns the top N active flows ranked by TotalBytes descending.
func (m *Manager) GetTopFlows(limit int) []*Flow {
	flows := m.GetActiveFlows()
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].TotalBytes > flows[j].TotalBytes
	})
	if limit > 0 && len(flows) > limit {
		flows = flows[:limit]
	}
	return flows
}

// GetStats returns aggregate counter statistics.
func (m *Manager) GetStats() FlowStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return FlowStats{
		TotalFlowsCreated: m.totalCreated,
		ActiveFlows:       len(m.flows),
		ClosedFlows:       len(m.closedHistory),
		TotalVolumeBytes:  m.totalBytes,
	}
}

// janitorLoop periodically sweeps for idle or timed out flows.
func (m *Manager) janitorLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case now := <-ticker.C:
			refTime := now
			m.mu.RLock()
			lastPkt := m.lastPktTime
			m.mu.RUnlock()

			// If last packet is historical (e.g. PCAP replay where timestamp is in the past),
			// avoid using wall clock time which would instantly evict all replay flows.
			if !lastPkt.IsZero() && (now.Sub(lastPkt) > time.Hour || lastPkt.After(now)) {
				refTime = lastPkt
			}
			m.Sweep(refTime)
		}
	}
}

// Sweep checks for idle flows relative to a reference time and moves them to history.
func (m *Manager) Sweep(refTime time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictStaleFlowsLocked(refTime)
}

func (m *Manager) sweep(refTime time.Time) {
	m.Sweep(refTime)
}

func (m *Manager) evictStaleFlowsLocked(refTime time.Time) {
	if refTime.IsZero() {
		refTime = time.Now()
	}

	for key, f := range m.flows {
		isIdle := refTime.Sub(f.LastSeen) > m.idleTimeout
		isActiveLimit := refTime.Sub(f.StartTime) > m.activeTimeout
		isClosed := f.State == "CLOSED"

		if isIdle || isActiveLimit || isClosed {
			if f.State == "ACTIVE" {
				f.State = "TIMED_OUT"
			}
			if len(m.closedHistory) >= 100 {
				m.closedHistory = m.closedHistory[1:]
			}
			m.closedHistory = append(m.closedHistory, f)
			delete(m.flows, key)
		}
	}
}

func (m *Manager) evictOldestLocked() {
	var oldestKey FlowKey
	var oldestTime time.Time
	first := true

	for key, f := range m.flows {
		if first || f.LastSeen.Before(oldestTime) {
			oldestTime = f.LastSeen
			oldestKey = key
			first = false
		}
	}

	if !first {
		f := m.flows[oldestKey]
		f.State = "TIMED_OUT"
		if len(m.closedHistory) >= 100 {
			m.closedHistory = m.closedHistory[1:]
		}
		m.closedHistory = append(m.closedHistory, f)
		delete(m.flows, oldestKey)
	}
}

// FormatFlowSummary returns a compact 1-line string representation.
func FormatFlowSummary(f *Flow) string {
	dur := f.Duration().Truncate(time.Millisecond)
	initEp := fmt.Sprintf("%s:%d", f.InitiatorIP, f.InitiatorPort)
	respEp := fmt.Sprintf("%s:%d", f.ResponderIP, f.ResponderPort)

	extra := ""
	if f.TLSSNI != "" {
		extra = " [SNI: " + f.TLSSNI + "]"
	} else if f.HTTPMethod != "" {
		extra = fmt.Sprintf(" [%s %s]", f.HTTPMethod, f.HTTPHost)
	} else if f.DNSQuery != "" {
		extra = " [DNS: " + f.DNSQuery + "]"
	}

	return fmt.Sprintf("%-5s %s <-> %s | Pkts: %d (Fwd: %d, Rev: %d) | Bytes: %d | Dur: %s%s",
		f.Protocol, initEp, respEp, f.TotalPackets, f.PacketsInitiator, f.PacketsResponder,
		f.TotalBytes, dur, extra)
}

// Close stops the background janitor.
func (m *Manager) Close() {
	select {
	case <-m.stopChan:
		return
	default:
		close(m.stopChan)
	}
}

