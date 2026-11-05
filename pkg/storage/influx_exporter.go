package storage

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/config"
)

type InfluxExporter struct {
	cfg        config.Config
	client     *http.Client
	endpoint   string
	mu         sync.Mutex
	buffer     []string
	lastFlush  time.Time
	batchSize  int
	flushChan  chan struct{}
	stopChan   chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

func NewInfluxExporter(cfg config.Config) *InfluxExporter {
	if !cfg.InfluxDB.Enabled {
		return &InfluxExporter{cfg: cfg}
	}

	endpoint := fmt.Sprintf("%s/api/v2/write?org=%s&bucket=%s&precision=ns",
		strings.TrimRight(cfg.InfluxDB.URL, "/"),
		url.QueryEscape(cfg.InfluxDB.Org),
		url.QueryEscape(cfg.InfluxDB.Bucket),
	)

	batchSize := cfg.InfluxDB.BatchSize
	if batchSize <= 0 {
		batchSize = 50
	}

	exp := &InfluxExporter{
		cfg:       cfg,
		client:    &http.Client{Timeout: 2 * time.Second},
		endpoint:  endpoint,
		batchSize: batchSize,
		buffer:    make([]string, 0, batchSize),
		lastFlush: time.Now(),
		flushChan: make(chan struct{}, 1),
		stopChan:  make(chan struct{}),
	}

	exp.wg.Add(1)
	go exp.flusher()
	return exp
}

func (exp *InfluxExporter) flusher() {
	defer exp.wg.Done()
	interval := exp.cfg.InfluxDB.FlushIntervalSeconds
	if interval <= 0 {
		interval = 2
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			exp.Flush()
		case <-exp.flushChan:
			exp.Flush()
		case <-exp.stopChan:
			return
		}
	}
}

func escapeTag(s string) string {
	s = strings.ReplaceAll(s, " ", "\\ ")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "=", "\\=")
	return s
}

func (exp *InfluxExporter) WritePacket(meta *cbridge.PacketMeta) {
	if !exp.cfg.InfluxDB.Enabled || meta == nil {
		return
	}

	exp.mu.Lock()
	defer exp.mu.Unlock()

	svc := meta.Service
	if svc == "" {
		svc = "unknown"
	}

	srcCountry := meta.SrcCountry
	if srcCountry == "" {
		srcCountry = "??"
	}
	dstCountry := meta.DstCountry
	if dstCountry == "" {
		dstCountry = "??"
	}

	line := fmt.Sprintf("network_traffic,src_ip=%s,dst_ip=%s,src_country=%s,dst_country=%s,protocol=%s,service=%s,is_broadcast=%t bytes=%di,payload_bytes=%di,count=1i %d",
		escapeTag(meta.SrcIP),
		escapeTag(meta.DstIP),
		escapeTag(srcCountry),
		escapeTag(dstCountry),
		escapeTag(meta.Protocol),
		escapeTag(svc),
		meta.IsBroadcast,
		meta.PacketSize,
		meta.PayloadSize,
		meta.Timestamp.UnixNano(),
	)
	exp.buffer = append(exp.buffer, line)

	if meta.DNSQuery != "" {
		dnsLine := fmt.Sprintf("dns_activity,client_ip=%s,query_name=%s,qtype=%d query_length=%di,count=1i %d",
			escapeTag(meta.SrcIP),
			escapeTag(meta.DNSQuery),
			meta.DNSType,
			len(meta.DNSQuery),
			meta.Timestamp.UnixNano(),
		)
		exp.buffer = append(exp.buffer, dnsLine)
	}

	if meta.TLSSNI != "" {
		sniLine := fmt.Sprintf("tls_activity,client_ip=%s,sni_domain=%s count=1i %d",
			escapeTag(meta.SrcIP),
			escapeTag(meta.TLSSNI),
			meta.Timestamp.UnixNano(),
		)
		exp.buffer = append(exp.buffer, sniLine)
	}

	if meta.HTTPMethod != "" {
		host := meta.HTTPHost
		if host == "" {
			host = "unknown"
		}
		httpLine := fmt.Sprintf("http_activity,client_ip=%s,method=%s,host=%s uri=%q,user_agent=%q,count=1i %d",
			escapeTag(meta.SrcIP),
			escapeTag(meta.HTTPMethod),
			escapeTag(host),
			meta.HTTPURI,
			meta.HTTPUserAgent,
			meta.Timestamp.UnixNano(),
		)
		exp.buffer = append(exp.buffer, httpLine)
	}

	if len(exp.buffer) >= exp.batchSize {
		select {
		case exp.flushChan <- struct{}{}:
		default:
		}
	}
}

func (exp *InfluxExporter) WriteAlerts(alerts []cbridge.Alert) {
	if !exp.cfg.InfluxDB.Enabled || len(alerts) == 0 {
		return
	}

	exp.mu.Lock()
	defer exp.mu.Unlock()

	for _, a := range alerts {
		srcCountry := a.SrcCountry
		if srcCountry == "" {
			srcCountry = "??"
		}
		dstCountry := a.DstCountry
		if dstCountry == "" {
			dstCountry = "??"
		}

		escapedMsg := strings.ReplaceAll(a.Message, "\"", "\\\"")
		line := fmt.Sprintf("ids_alerts,severity=%s,alert_type=%s,src_ip=%s,src_country=%s,dst_ip=%s,dst_country=%s,protocol=%s message=\"%s\",count=1i %d",
			escapeTag(a.Severity),
			escapeTag(a.AlertType),
			escapeTag(a.SrcIP),
			escapeTag(srcCountry),
			escapeTag(a.DstIP),
			escapeTag(dstCountry),
			escapeTag(a.Protocol),
			escapedMsg,
			a.Timestamp.UnixNano(),
		)
		exp.buffer = append(exp.buffer, line)
	}

	if len(exp.buffer) >= exp.batchSize {
		select {
		case exp.flushChan <- struct{}{}:
		default:
		}
	}
}

func (exp *InfluxExporter) Flush() {
	exp.mu.Lock()
	if len(exp.buffer) == 0 {
		exp.mu.Unlock()
		return
	}

	batch := strings.Join(exp.buffer, "\n")
	exp.buffer = exp.buffer[:0]
	exp.lastFlush = time.Now()
	exp.mu.Unlock()

	req, err := http.NewRequest("POST", exp.endpoint, bytes.NewBufferString(batch))
	if err != nil {
		return
	}

	req.Header.Set("Authorization", "Token "+exp.cfg.InfluxDB.Token)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	resp, err := exp.client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func (exp *InfluxExporter) Close() {
	if !exp.cfg.InfluxDB.Enabled {
		return
	}
	exp.stopOnce.Do(func() {
		close(exp.stopChan)
		exp.wg.Wait()
		exp.Flush()
	})
}
