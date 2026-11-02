package cbridge

/*
#cgo CFLAGS: -I../../c_core/include
#cgo LDFLAGS: -L../../c_core -lcmonitor -lpcap
#include <stdlib.h>
#include <string.h>
#include "cmonitor/packet.h"
#include "cmonitor/parser.h"
#include "cmonitor/capture.h"
#include "cmonitor/ids.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unsafe"
)

var (
	ErrTimeout = errors.New("capture timeout")
	ErrEOF     = io.EOF
)

type PacketMeta struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcMAC      string
	DstMAC      string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	Service     string
	PacketSize  uint32
	PayloadSize uint32
	TCPFlags    uint8
	TCPFlagsStr string
	DNSQuery      string
	DNSType       uint16
	TLSSNI        string
	HTTPMethod    string
	HTTPHost      string
	HTTPURI       string
	HTTPUserAgent string
	ARPOpcode     uint16
	VLANID        uint16
	IsBroadcast   bool

	// GeoIP Enrichment
	SrcCountry string
	SrcFlag    string
	DstCountry string
	DstFlag    string
	SrcOrg     string
	DstOrg     string
}

type Alert struct {
	Timestamp time.Time
	Severity  string
	AlertType string
	Message   string
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Details   string

	// GeoIP Enrichment
	SrcCountry string
	SrcFlag    string
	DstCountry string
	DstFlag    string
}

type Capture struct {
	mu     sync.RWMutex
	handle *C.cmonitor_capture_t
}

func OpenLive(device, bpfFilter string, promisc bool, snaplen int) (*Capture, error) {
	cDev := C.CString(device)
	defer C.free(unsafe.Pointer(cDev))

	var cFilter *C.char
	if bpfFilter != "" {
		cFilter = C.CString(bpfFilter)
		defer C.free(unsafe.Pointer(cFilter))
	}

	cPromisc := C.int(0)
	if promisc {
		cPromisc = 1
	}

	errbuf := make([]C.char, 256)
	handle := C.cmonitor_capture_open_live(cDev, cFilter, cPromisc, C.int(snaplen), &errbuf[0])
	if handle == nil {
		return nil, fmt.Errorf("failed to open live capture on %s: %s", device, C.GoString(&errbuf[0]))
	}

	return &Capture{handle: handle}, nil
}

func OpenOffline(filepath, bpfFilter string) (*Capture, error) {
	cPath := C.CString(filepath)
	defer C.free(unsafe.Pointer(cPath))

	var cFilter *C.char
	if bpfFilter != "" {
		cFilter = C.CString(bpfFilter)
		defer C.free(unsafe.Pointer(cFilter))
	}

	errbuf := make([]C.char, 256)
	handle := C.cmonitor_capture_open_offline(cPath, cFilter, &errbuf[0])
	if handle == nil {
		return nil, fmt.Errorf("failed to open offline capture %s: %s", filepath, C.GoString(&errbuf[0]))
	}

	return &Capture{handle: handle}, nil
}

func (c *Capture) Next() (*PacketMeta, []byte, error) {
	c.mu.RLock()
	h := c.handle
	if h == nil {
		c.mu.RUnlock()
		return nil, nil, errors.New("capture handle closed")
	}

	var cMeta C.cmonitor_packet_meta_t
	var rawData *C.uint8_t
	var rawLen C.uint32_t

	res := C.cmonitor_capture_next(h, &cMeta, &rawData, &rawLen)
	c.mu.RUnlock()
	if res == 0 {
		return nil, nil, ErrTimeout
	}
	if res == -2 {
		return nil, nil, ErrEOF
	}
	if res < 0 {
		return nil, nil, errors.New("capture error")
	}

	meta := &PacketMeta{
		Timestamp:   time.Unix(int64(cMeta.ts_sec), int64(cMeta.ts_usec)*1000).UTC(),
		SrcIP:       C.GoString(&cMeta.src_ip[0]),
		DstIP:       C.GoString(&cMeta.dst_ip[0]),
		SrcMAC:      C.GoString(&cMeta.src_mac[0]),
		DstMAC:      C.GoString(&cMeta.dst_mac[0]),
		SrcPort:     uint16(cMeta.src_port),
		DstPort:     uint16(cMeta.dst_port),
		Protocol:    C.GoString(&cMeta.protocol[0]),
		Service:     C.GoString(&cMeta.service[0]),
		PacketSize:  uint32(cMeta.packet_size),
		PayloadSize: uint32(cMeta.payload_size),
		TCPFlags:    uint8(cMeta.tcp_flags),
		TCPFlagsStr: C.GoString(&cMeta.tcp_flags_str[0]),
		DNSQuery:      C.GoString(&cMeta.dns_query[0]),
		DNSType:       uint16(cMeta.dns_type),
		TLSSNI:        C.GoString(&cMeta.tls_sni[0]),
		HTTPMethod:    C.GoString(&cMeta.http_method[0]),
		HTTPHost:      C.GoString(&cMeta.http_host[0]),
		HTTPURI:       C.GoString(&cMeta.http_uri[0]),
		HTTPUserAgent: C.GoString(&cMeta.http_user_agent[0]),
		ARPOpcode:     uint16(cMeta.arp_opcode),
		VLANID:        uint16(cMeta.vlan_id),
		IsBroadcast:   cMeta.is_broadcast != 0,
	}

	var rawCopy []byte
	if rawLen > 0 && rawData != nil {
		rawCopy = C.GoBytes(unsafe.Pointer(rawData), C.int(rawLen))
	}

	return meta, rawCopy, nil
}

func (c *Capture) SetBPFFilter(filter string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handle == nil {
		return errors.New("capture handle closed")
	}
	var cFilter *C.char
	if filter != "" {
		cFilter = C.CString(filter)
		defer C.free(unsafe.Pointer(cFilter))
	}
	errbuf := make([]C.char, 256)
	res := C.cmonitor_capture_set_bpf(c.handle, cFilter, &errbuf[0])
	if res != 0 {
		return fmt.Errorf("BPF error: %s", C.GoString(&errbuf[0]))
	}
	return nil
}

func (c *Capture) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handle != nil {
		C.cmonitor_capture_close(c.handle)
		c.handle = nil
	}
}

type IDSEngine struct {
	handle *C.cmonitor_ids_t
}

type IDSConfig struct {
	Enabled            bool
	PortScanThreshold  int
	PortScanWindowSec  int
	SYNFloodThreshold  int
	SYNFloodWindowSec  int
	BandwidthSpikeBps  uint64
	BandwidthWindowSec int
	DNSTunnelLen       int
}

func DefaultIDSConfig() IDSConfig {
	return IDSConfig{
		Enabled:            true,
		PortScanThreshold:  15,
		PortScanWindowSec:  10,
		SYNFloodThreshold:  100,
		SYNFloodWindowSec:  2,
		BandwidthSpikeBps:  10000000,
		BandwidthWindowSec: 2,
		DNSTunnelLen:       60,
	}
}

func NewIDSEngine(cfg IDSConfig) *IDSEngine {
	var cCfg C.cmonitor_ids_config_t
	if cfg.Enabled {
		cCfg.enabled = 1
	} else {
		cCfg.enabled = 0
	}
	cCfg.port_scan_threshold = C.int(cfg.PortScanThreshold)
	cCfg.port_scan_window_sec = C.int(cfg.PortScanWindowSec)
	cCfg.syn_flood_threshold = C.int(cfg.SYNFloodThreshold)
	cCfg.syn_flood_window_sec = C.int(cfg.SYNFloodWindowSec)
	cCfg.bw_spike_bytes_sec = C.size_t(cfg.BandwidthSpikeBps)
	cCfg.bw_window_sec = C.int(cfg.BandwidthWindowSec)
	cCfg.dns_tunnel_len = C.size_t(cfg.DNSTunnelLen)

	handle := C.cmonitor_ids_init(&cCfg)
	return &IDSEngine{handle: handle}
}

func (ids *IDSEngine) Analyze(meta *PacketMeta) []Alert {
	if ids.handle == nil || meta == nil {
		return nil
	}

	var cMeta C.cmonitor_packet_meta_t
	cMeta.ts_sec = C.int64_t(meta.Timestamp.Unix())
	cMeta.ts_usec = C.int64_t(meta.Timestamp.Nanosecond() / 1000)
	cMeta.src_port = C.uint16_t(meta.SrcPort)
	cMeta.dst_port = C.uint16_t(meta.DstPort)
	cMeta.packet_size = C.uint32_t(meta.PacketSize)
	cMeta.payload_size = C.uint32_t(meta.PayloadSize)
	cMeta.tcp_flags = C.uint8_t(meta.TCPFlags)
	cMeta.arp_opcode = C.uint16_t(meta.ARPOpcode)
	if meta.IsBroadcast {
		cMeta.is_broadcast = 1
	}

	copyString(&cMeta.src_ip[0], meta.SrcIP, 64)
	copyString(&cMeta.dst_ip[0], meta.DstIP, 64)
	copyString(&cMeta.src_mac[0], meta.SrcMAC, 18)
	copyString(&cMeta.dst_mac[0], meta.DstMAC, 18)
	copyString(&cMeta.protocol[0], meta.Protocol, 16)
	copyString(&cMeta.service[0], meta.Service, 32)
	copyString(&cMeta.dns_query[0], meta.DNSQuery, 256)

	cAlerts := make([]C.cmonitor_alert_t, 16)
	count := C.cmonitor_ids_analyze(ids.handle, &cMeta, &cAlerts[0], 16)

	if count <= 0 {
		return nil
	}

	alerts := make([]Alert, count)
	for i := 0; i < int(count); i++ {
		ca := cAlerts[i]
		alerts[i] = Alert{
			Timestamp: time.Unix(int64(ca.ts_sec), int64(ca.ts_usec)*1000).UTC(),
			Severity:  C.GoString(C.cmonitor_severity_str(ca.severity)),
			AlertType: C.GoString(&ca.alert_type[0]),
			Message:   C.GoString(&ca.message[0]),
			SrcIP:     C.GoString(&ca.src_ip[0]),
			DstIP:     C.GoString(&ca.dst_ip[0]),
			SrcPort:   uint16(ca.src_port),
			DstPort:   uint16(ca.dst_port),
			Protocol:  C.GoString(&ca.protocol[0]),
			Details:   C.GoString(&ca.details[0]),
		}
	}

	return alerts
}

func (ids *IDSEngine) Close() {
	if ids.handle != nil {
		C.cmonitor_ids_free(ids.handle)
		ids.handle = nil
	}
}

func copyString(dest *C.char, src string, maxLen int) {
	if maxLen <= 0 || dest == nil {
		return
	}
	slice := unsafe.Slice((*byte)(unsafe.Pointer(dest)), maxLen)
	n := copy(slice[:maxLen-1], src)
	slice[n] = 0
}
