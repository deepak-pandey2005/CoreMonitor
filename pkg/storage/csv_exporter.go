package storage

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/config"
)

type CSVExporter struct {
	cfg          config.Config
	mu           sync.Mutex
	pktFile      *os.File
	pktWriter    *csv.Writer
	alertFile    *os.File
	alertWriter  *csv.Writer
	lastRotation time.Time
	pktCount     int
}

func NewCSVExporter(cfg config.Config) (*CSVExporter, error) {
	if !cfg.Storage.CSVEnabled {
		return &CSVExporter{cfg: cfg}, nil
	}

	if cfg.Storage.CSVRotateSeconds <= 0 {
		cfg.Storage.CSVRotateSeconds = 3600
	}

	if err := os.MkdirAll(cfg.Storage.CSVDir, 0755); err != nil {
		return nil, err
	}

	exp := &CSVExporter{cfg: cfg}
	if err := exp.rotateFiles(); err != nil {
		return nil, err
	}
	return exp, nil
}

func (exp *CSVExporter) rotateFiles() error {
	rotSec := exp.cfg.Storage.CSVRotateSeconds
	if rotSec <= 0 {
		rotSec = 3600
	}
	now := time.Now().UTC()
	if exp.pktFile != nil && now.Sub(exp.lastRotation) < time.Duration(rotSec)*time.Second {
		return nil
	}

	exp.closeFiles()

	tsStr := now.Format("20060102_150405")
	pktPath := filepath.Join(exp.cfg.Storage.CSVDir, fmt.Sprintf("traffic_%s.csv", tsStr))
	pktExists := fileExists(pktPath)

	pf, err := os.OpenFile(pktPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	exp.pktFile = pf
	exp.pktWriter = csv.NewWriter(pf)

	if !pktExists {
		_ = exp.pktWriter.Write([]string{
			"timestamp", "src_ip", "dst_ip", "src_country", "dst_country",
			"src_port", "dst_port", "protocol", "service", "packet_size", "payload_size",
			"tcp_flags", "dns_query", "dns_type", "tls_sni", "http_method", "http_host", "http_uri", "src_mac", "dst_mac",
		})
		exp.pktWriter.Flush()
	}

	alertPath := filepath.Join(exp.cfg.Storage.CSVDir, fmt.Sprintf("alerts_%s.csv", tsStr))
	alertExists := fileExists(alertPath)

	af, err := os.OpenFile(alertPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	exp.alertFile = af
	exp.alertWriter = csv.NewWriter(af)

	if !alertExists {
		_ = exp.alertWriter.Write([]string{
			"timestamp", "severity", "alert_type", "message",
			"src_ip", "src_country", "dst_ip", "dst_country", "src_port", "dst_port", "protocol", "details",
		})
		exp.alertWriter.Flush()
	}

	exp.lastRotation = now
	return nil
}

func (exp *CSVExporter) WritePacket(meta *cbridge.PacketMeta) {
	if !exp.cfg.Storage.CSVEnabled || meta == nil {
		return
	}
	exp.mu.Lock()
	defer exp.mu.Unlock()

	_ = exp.rotateFiles()
	if exp.pktWriter == nil {
		return
	}

	_ = exp.pktWriter.Write([]string{
		meta.Timestamp.Format(time.RFC3339Nano),
		meta.SrcIP,
		meta.DstIP,
		meta.SrcCountry,
		meta.DstCountry,
		strconv.Itoa(int(meta.SrcPort)),
		strconv.Itoa(int(meta.DstPort)),
		meta.Protocol,
		meta.Service,
		strconv.Itoa(int(meta.PacketSize)),
		strconv.Itoa(int(meta.PayloadSize)),
		meta.TCPFlagsStr,
		meta.DNSQuery,
		strconv.Itoa(int(meta.DNSType)),
		meta.TLSSNI,
		meta.HTTPMethod,
		meta.HTTPHost,
		meta.HTTPURI,
		meta.SrcMAC,
		meta.DstMAC,
	})
	exp.pktCount++
	if exp.pktCount%100 == 0 {
		exp.pktWriter.Flush()
	}
}

func (exp *CSVExporter) WriteAlerts(alerts []cbridge.Alert) {
	if !exp.cfg.Storage.CSVEnabled || len(alerts) == 0 {
		return
	}
	exp.mu.Lock()
	defer exp.mu.Unlock()

	_ = exp.rotateFiles()
	if exp.alertWriter == nil {
		return
	}

	for _, a := range alerts {
		_ = exp.alertWriter.Write([]string{
			a.Timestamp.Format(time.RFC3339Nano),
			a.Severity,
			a.AlertType,
			a.Message,
			a.SrcIP,
			a.SrcCountry,
			a.DstIP,
			a.DstCountry,
			strconv.Itoa(int(a.SrcPort)),
			strconv.Itoa(int(a.DstPort)),
			a.Protocol,
			a.Details,
		})
	}
	exp.alertWriter.Flush()
}

func (exp *CSVExporter) closeFiles() {
	if exp.pktWriter != nil {
		exp.pktWriter.Flush()
		exp.pktWriter = nil
	}
	if exp.pktFile != nil {
		_ = exp.pktFile.Close()
		exp.pktFile = nil
	}
	if exp.alertWriter != nil {
		exp.alertWriter.Flush()
		exp.alertWriter = nil
	}
	if exp.alertFile != nil {
		_ = exp.alertFile.Close()
		exp.alertFile = nil
	}
	exp.pktCount = 0
}

func (exp *CSVExporter) Close() {
	exp.mu.Lock()
	defer exp.mu.Unlock()
	exp.closeFiles()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
