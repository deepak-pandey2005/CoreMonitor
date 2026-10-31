package engine

import (
	"sync"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/config"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/storage"
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
}

type ratePoint struct {
	ts    time.Time
	bytes uint64
}

type Engine struct {
	cfg     config.Config
	capture *cbridge.Capture
	ids     *cbridge.IDSEngine

	csvExp    *storage.CSVExporter
	pcapExp   *storage.PCAPExporter
	influxExp *storage.InfluxExporter

	mu       sync.RWMutex
	stats    Stats
	stopChan chan struct{}
	running  bool
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

	eng := &Engine{
		cfg:       cfg,
		capture:   capture,
		ids:       cbridge.NewIDSEngine(idsCfg),
		csvExp:    csvExp,
		pcapExp:   pcapExp,
		influxExp: influxExp,
		stopChan:  make(chan struct{}),
		stats: Stats{
			StartTime:       time.Now(),
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
			return nil
		}
		if err != nil {
			return err
		}

		alerts := e.ids.Analyze(meta)

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
	}
}

func (e *Engine) Stop() {
	if e.running {
		close(e.stopChan)
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
