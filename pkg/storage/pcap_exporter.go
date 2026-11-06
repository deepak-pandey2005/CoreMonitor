package storage

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/config"
)

type PCAPExporter struct {
	cfg          config.Config
	mu           sync.Mutex
	file         *os.File
	bufWriter    *bufio.Writer
	lastRotation time.Time
}

func NewPCAPExporter(cfg config.Config) (*PCAPExporter, error) {
	if !cfg.Storage.PCAPEnabled {
		return &PCAPExporter{cfg: cfg}, nil
	}

	if cfg.Storage.PCAPRotateSeconds <= 0 {
		cfg.Storage.PCAPRotateSeconds = 3600
	}

	if err := os.MkdirAll(cfg.Storage.PCAPDir, 0755); err != nil {
		return nil, err
	}

	exp := &PCAPExporter{cfg: cfg}
	if err := exp.rotateFiles(); err != nil {
		return nil, err
	}
	return exp, nil
}

func (exp *PCAPExporter) rotateFiles() error {
	rotSec := exp.cfg.Storage.PCAPRotateSeconds
	if rotSec <= 0 {
		rotSec = 3600
	}
	now := time.Now().UTC()
	if exp.file != nil && now.Sub(exp.lastRotation) < time.Duration(rotSec)*time.Second {
		return nil
	}

	if exp.file != nil {
		if exp.bufWriter != nil {
			_ = exp.bufWriter.Flush()
			exp.bufWriter = nil
		}
		_ = exp.file.Close()
		exp.file = nil
	}

	tsStr := now.Format("20060102_150405")
	pcapPath := filepath.Join(exp.cfg.Storage.PCAPDir, fmt.Sprintf("traffic_%s.pcap", tsStr))
	if fileExists(pcapPath) {
		tsStr = now.Format("20060102_150405_000000")
		pcapPath = filepath.Join(exp.cfg.Storage.PCAPDir, fmt.Sprintf("traffic_%s.pcap", tsStr))
	}

	f, err := os.OpenFile(pcapPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	// Write standard PCAP global header (24 bytes)
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4) // Magic number
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // Major version
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // Minor version
	binary.LittleEndian.PutUint32(hdr[8:12], 0)         // GMT to local correction
	binary.LittleEndian.PutUint32(hdr[12:16], 0)        // Accuracy of timestamps
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)    // Max snapshot length
	binary.LittleEndian.PutUint32(hdr[20:24], 1)        // Data link type: 1 = Ethernet

	exp.file = f
	exp.bufWriter = bufio.NewWriterSize(f, 65536)
	if _, err := exp.bufWriter.Write(hdr); err != nil {
		_ = f.Close()
		exp.file = nil
		exp.bufWriter = nil
		return err
	}

	exp.lastRotation = now
	return nil
}

func (exp *PCAPExporter) WriteRawPacket(ts time.Time, rawData []byte, origLen uint32) {
	if !exp.cfg.Storage.PCAPEnabled || len(rawData) == 0 {
		return
	}
	exp.mu.Lock()
	defer exp.mu.Unlock()

	_ = exp.rotateFiles()
	if exp.bufWriter == nil {
		return
	}

	// PCAP packet header (16 bytes)
	recHdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(recHdr[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(recHdr[4:8], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(recHdr[8:12], uint32(len(rawData)))
	binary.LittleEndian.PutUint32(recHdr[12:16], origLen)

	_, _ = exp.bufWriter.Write(recHdr)
	_, _ = exp.bufWriter.Write(rawData)
}

func (exp *PCAPExporter) Close() {
	exp.mu.Lock()
	defer exp.mu.Unlock()
	if exp.bufWriter != nil {
		_ = exp.bufWriter.Flush()
		exp.bufWriter = nil
	}
	if exp.file != nil {
		_ = exp.file.Close()
		exp.file = nil
	}
}
