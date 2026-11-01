package engine

import (
	"errors"
	"sync"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/config"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/flow"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/geoip"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/ips"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/siem"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/storage"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/webhook"
)

type Stats struct {
	StartTime       time.Time
	TotalPackets    uint64
	TotalBytes      uint64
	ProtocolCounts  map[string]uint64
	TopTalkersBytes map[string]uint64
	RecentAlerts    []cbridge.Alert
	RecentPackets   []*cbridge.PacketMeta
	RateHistory     []ratePoint
	BytesPerSec     float64
	PktsPerSec      float64
	BannedHosts     []ips.BannedHost
	ActiveFlows     []*flow.Flow
	FlowStats       flow.FlowStats
	ActiveBPFFilter string
	ReplaySpeed     float64
	IsReplay        bool
	ReplayFinished  bool
	SIEMStats       siem.ExporterStats
}

type ratePoint struct {
	ts    time.Time
	bytes uint64
}

type Engine struct {
	cfg         config.Config
	capture     *cbridge.Capture
	ids         *cbridge.IDSEngine
	ipsMgr      *ips.Manager
	flowMgr     *flow.Manager
	webhookDisp *webhook.Dispatcher
	siemExp     *siem.Exporter

	csvExp    *storage.CSVExporter
	pcapExp   *storage.PCAPExporter
	influxExp *storage.InfluxExporter

	mu         sync.RWMutex
	stats      Stats
	stopChan   chan struct{}
	stopOnce   sync.Once
	running    bool
	pacer      *ReplayPacer
	isReplay   bool
	replayDone bool
}

func NewEngine(cfg config.Config, capture *cbridge.Capture) (*Engine, error) {
	idsCfg := cbridge.IDSConfig{
		Enabled:            cfg.IDS.Enabled,
		PortScanThreshold:  cfg.IDS.PortScanThreshold,
		PortScanWindowSec:  cfg.IDS.PortScanWindowSeconds,
		SYNFloodThreshold:  cfg.IDS.SYNFloodThreshold,
		SYNFloodWindowSec:  cfg.IDS.SYNFloodWindowSeconds,
		BandwidthSpikeBps:  cfg.IDS.BandwidthSpikeBytesPerSec,
		BandwidthWindowSec: cfg.IDS.BandwidthWindowSeconds,
		DNSTunnelLen:       cfg.IDS.DNSTunnelAnomalyLength,
	}

	csvExp, err := storage.NewCSVExporter(cfg)
	if err != nil {
		return nil, err
	}

	pcapExp, err := storage.NewPCAPExporter(cfg)
	if err != nil {
		csvExp.Close()
		return nil, err
	}

	influxExp := storage.NewInfluxExporter(cfg)
	ipsMgr := ips.NewManager(cfg.IPS)

	var flowMgr *flow.Manager
	if cfg.Flow.Enabled {
		idleDur := time.Duration(cfg.Flow.IdleTimeoutSeconds) * time.Second
		activeDur := time.Duration(cfg.Flow.ActiveTimeoutSeconds) * time.Second
		flowMgr = flow.NewManager(idleDur, activeDur)
	}

	eng := &Engine{
		cfg:         cfg,
		capture:     capture,
		ids:         cbridge.NewIDSEngine(idsCfg),
		ipsMgr:      ipsMgr,
		flowMgr:     flowMgr,
		webhookDisp: webhook.NewDispatcher(cfg.Webhook),
		siemExp:     siem.NewExporter(cfg.SIEM),
		csvExp:      csvExp,
		pcapExp:     pcapExp,
		influxExp:   influxExp,
		stopChan:  make(chan struct{}),
		stats: Stats{
			StartTime:       time.Now(),
			ActiveBPFFilter: cfg.Network.BPFFilter,
			ProtocolCounts:  make(map[string]uint64),
			TopTalkersBytes: make(map[string]uint64),
			RecentAlerts:    make([]cbridge.Alert, 0, 50),
			RecentPackets:   make([]*cbridge.PacketMeta, 0, 20),
			RateHistory:     make([]ratePoint, 0, 30),
		},
	}

	return eng, nil
}

func (e *Engine) ProcessLoop() error {
	e.running = true
	defer func() {
		e.running = false
	}()

	for {
		select {
		case <-e.stopChan:
			return nil
		default:
		}

		meta, raw, err := e.capture.Next()
		if err == cbridge.ErrTimeout {
			continue
		}
		if err == cbridge.ErrEOF {
			e.mu.Lock()
			e.replayDone = true
			e.stats.ReplayFinished = true
			e.mu.Unlock()
			return nil
		}
		if err != nil {
			return err
		}

		// Replay Rate Governor Pacing
		if e.pacer != nil {
			if err := e.pacer.Pace(e.stopChan, meta.Timestamp); err != nil {
				return nil
			}
		}

		// GeoIP Enrichment
		srcLoc := geoip.Lookup(meta.SrcIP)
		dstLoc := geoip.Lookup(meta.DstIP)
		meta.SrcCountry = srcLoc.CountryCode
		meta.SrcFlag = srcLoc.Flag
		meta.SrcOrg = srcLoc.Org
		meta.DstCountry = dstLoc.CountryCode
		meta.DstFlag = dstLoc.Flag
		meta.DstOrg = dstLoc.Org

		alerts := e.ids.Analyze(meta)
		for i := range alerts {
			alerts[i].SrcCountry = srcLoc.CountryCode
			alerts[i].SrcFlag = srcLoc.Flag
			alerts[i].DstCountry = dstLoc.CountryCode
			alerts[i].DstFlag = dstLoc.Flag

			jailed := false
			// Active Defense (IPS)
			if e.ipsMgr != nil {
				jailed = e.ipsMgr.HandleAlert(alerts[i])
			}

			// Webhook Alert Dispatch
			if e.webhookDisp != nil {
				e.webhookDisp.Dispatch(alerts[i], jailed)
			}

			// SIEM Alert Dispatch (CEF / Syslog)
			if e.siemExp != nil {
				e.siemExp.SendAlert(alerts[i], jailed)
			}
		}

		// Exporters
		e.csvExp.WritePacket(meta)
		if len(alerts) > 0 {
			e.csvExp.WriteAlerts(alerts)
		}
		if len(raw) > 0 {
			e.pcapExp.WriteRawPacket(meta.Timestamp, raw, meta.PacketSize)
		}
		e.influxExp.WritePacket(meta)
		if len(alerts) > 0 {
			e.influxExp.WriteAlerts(alerts)
		}

		// Ingest into Flow Manager
		if e.flowMgr != nil {
			e.flowMgr.Ingest(meta)
		}

		// Update in-memory stats
		e.updateStats(meta, alerts)
	}
}

func (e *Engine) updateStats(meta *cbridge.PacketMeta, alerts []cbridge.Alert) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	e.stats.TotalPackets++
	e.stats.TotalBytes += uint64(meta.PacketSize)
	e.stats.ProtocolCounts[meta.Protocol]++

	if meta.SrcIP != "" && meta.SrcIP != "unknown" {
		e.stats.TopTalkersBytes[meta.SrcIP] += uint64(meta.PacketSize)
	}

	if len(e.stats.RecentPackets) >= 20 {
		e.stats.RecentPackets = e.stats.RecentPackets[1:]
	}
	e.stats.RecentPackets = append(e.stats.RecentPackets, meta)

	for _, a := range alerts {
		if len(e.stats.RecentAlerts) >= 50 {
			e.stats.RecentAlerts = e.stats.RecentAlerts[1:]
		}
		e.stats.RecentAlerts = append(e.stats.RecentAlerts, a)
	}

	e.stats.RateHistory = append(e.stats.RateHistory, ratePoint{ts: now, bytes: uint64(meta.PacketSize)})
	cutoff := now.Add(-2 * time.Second)
	idx := 0
	for idx < len(e.stats.RateHistory) && e.stats.RateHistory[idx].ts.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		e.stats.RateHistory = e.stats.RateHistory[idx:]
	}

	if len(e.stats.RateHistory) > 1 {
		dt := now.Sub(e.stats.RateHistory[0].ts).Seconds()
		if dt > 0.1 {
			var bSum uint64
			for _, pt := range e.stats.RateHistory {
				bSum += pt.bytes
			}
			e.stats.BytesPerSec = float64(bSum) / dt
			e.stats.PktsPerSec = float64(len(e.stats.RateHistory)) / dt
		}
	}
}

func (e *Engine) GetStats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	protoCopy := make(map[string]uint64, len(e.stats.ProtocolCounts))
	for k, v := range e.stats.ProtocolCounts {
		protoCopy[k] = v
	}

	talkersCopy := make(map[string]uint64, len(e.stats.TopTalkersBytes))
	for k, v := range e.stats.TopTalkersBytes {
		talkersCopy[k] = v
	}

	alertsCopy := make([]cbridge.Alert, len(e.stats.RecentAlerts))
	copy(alertsCopy, e.stats.RecentAlerts)

	pktsCopy := make([]*cbridge.PacketMeta, len(e.stats.RecentPackets))
	copy(pktsCopy, e.stats.RecentPackets)

	var bannedCopy []ips.BannedHost
	if e.ipsMgr != nil {
		bannedCopy = e.ipsMgr.GetBannedHosts()
	}

	var activeFlows []*flow.Flow
	var fStats flow.FlowStats
	if e.flowMgr != nil {
		activeFlows = e.flowMgr.GetTopFlows(25)
		fStats = e.flowMgr.GetStats()
	}

	var siemStats siem.ExporterStats
	if e.siemExp != nil {
		siemStats = e.siemExp.GetStats()
	}

	return Stats{
		StartTime:       e.stats.StartTime,
		TotalPackets:    e.stats.TotalPackets,
		TotalBytes:      e.stats.TotalBytes,
		ProtocolCounts:  protoCopy,
		TopTalkersBytes: talkersCopy,
		RecentAlerts:    alertsCopy,
		RecentPackets:   pktsCopy,
		BytesPerSec:     e.stats.BytesPerSec,
		PktsPerSec:      e.stats.PktsPerSec,
		BannedHosts:     bannedCopy,
		ActiveFlows:     activeFlows,
		FlowStats:       fStats,
		ActiveBPFFilter: e.stats.ActiveBPFFilter,
		ReplaySpeed:     e.stats.ReplaySpeed,
		IsReplay:        e.stats.IsReplay,
		ReplayFinished:  e.stats.ReplayFinished,
		SIEMStats:       siemStats,
	}
}

// SetReplaySpeed configures or updates the PCAP playback speed multiplier and delay ceiling.
func (e *Engine) SetReplaySpeed(speed float64, maxDelay time.Duration) {
	e.mu.Lock()
	e.isReplay = true
	if e.pacer == nil {
		e.pacer = NewReplayPacer(PacerConfig{
			SpeedMultiplier: speed,
			MaxDelay:        maxDelay,
		})
	} else {
		e.pacer.SetSpeed(speed)
	}
	e.stats.ReplaySpeed = speed
	e.stats.IsReplay = true
	e.mu.Unlock()
}

// SetReplayPacer attaches an existing ReplayPacer instance.
func (e *Engine) SetReplayPacer(pacer *ReplayPacer) {
	e.mu.Lock()
	e.pacer = pacer
	e.isReplay = true
	if pacer != nil {
		e.stats.ReplaySpeed = pacer.GetSpeed()
		e.stats.IsReplay = true
	}
	e.mu.Unlock()
}

// IsReplay reports if the engine is running in PCAP replay mode.
func (e *Engine) IsReplay() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isReplay
}

// IsReplayFinished reports if an offline PCAP has reached EOF.
func (e *Engine) IsReplayFinished() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.replayDone
}

func (e *Engine) SetBPFFilter(filter string) error {
	if e.capture == nil {
		return errors.New("capture handle not open")
	}
	err := e.capture.SetBPFFilter(filter)
	if err == nil {
		e.mu.Lock()
		e.stats.ActiveBPFFilter = filter
		e.mu.Unlock()
	}
	return err
}

func (e *Engine) GetBPFFilter() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats.ActiveBPFFilter
}

func (e *Engine) GetIPS() *ips.Manager {
	return e.ipsMgr
}

func (e *Engine) GetFlowManager() *flow.Manager {
	return e.flowMgr
}

func (e *Engine) GetSIEMExporter() *siem.Exporter {
	return e.siemExp
}

func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		close(e.stopChan)
	})
	if e.flowMgr != nil {
		e.flowMgr.Close()
	}
	if e.webhookDisp != nil {
		e.webhookDisp.Close()
	}
	if e.siemExp != nil {
		e.siemExp.Close()
	}
	if e.ipsMgr != nil {
		e.ipsMgr.Cleanup()
	}
	if e.capture != nil {
		e.capture.Close()
	}
	if e.ids != nil {
		e.ids.Close()
	}
	if e.csvExp != nil {
		e.csvExp.Close()
	}
	if e.pcapExp != nil {
		e.pcapExp.Close()
	}
	if e.influxExp != nil {
		e.influxExp.Close()
	}
}
