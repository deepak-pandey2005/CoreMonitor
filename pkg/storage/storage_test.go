package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/config"
)

func TestCSVAndPCAPExporters(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coremonitor_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := *config.DefaultConfig()
	cfg.Storage.CSVDir = tempDir
	cfg.Storage.PCAPDir = tempDir

	csvExp, err := NewCSVExporter(cfg)
	if err != nil {
		t.Fatalf("failed to create CSV exporter: %v", err)
	}
	defer csvExp.Close()

	pcapExp, err := NewPCAPExporter(cfg)
	if err != nil {
		t.Fatalf("failed to create PCAP exporter: %v", err)
	}
	defer pcapExp.Close()

	meta := &cbridge.PacketMeta{
		Timestamp:  time.Now().UTC(),
		SrcIP:      "192.168.1.10",
		DstIP:      "1.1.1.1",
		SrcPort:    12345,
		DstPort:    53,
		Protocol:   "UDP",
		Service:    "DNS",
		PacketSize: 60,
	}

	csvExp.WritePacket(meta)
	csvExp.WriteAlerts([]cbridge.Alert{
		{
			Timestamp: time.Now().UTC(),
			Severity:  "HIGH",
			AlertType: "TEST_ALERT",
			Message:   "Test Alert Message",
			SrcIP:     "192.168.1.10",
		},
	})

	rawDummyPacket := make([]byte, 60)
	pcapExp.WriteRawPacket(meta.Timestamp, rawDummyPacket, 60)

	csvExp.Close()
	pcapExp.Close()

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	var hasCSV, hasPCAP, hasAlerts bool
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) == ".csv" && len(name) > 8 && name[:8] == "traffic_" {
			hasCSV = true
		}
		if filepath.Ext(name) == ".csv" && len(name) > 7 && name[:7] == "alerts_" {
			hasAlerts = true
		}
		if filepath.Ext(name) == ".pcap" {
			hasPCAP = true
		}
	}

	if !hasCSV {
		t.Errorf("traffic CSV file was not created in %s", tempDir)
	}
	if !hasAlerts {
		t.Errorf("alerts CSV file was not created in %s", tempDir)
	}
	if !hasPCAP {
		t.Errorf("traffic PCAP file was not created in %s", tempDir)
	}
}

func TestStorageBufferedThroughput(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coremonitor_bench")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := *config.DefaultConfig()
	cfg.Storage.CSVDir = tempDir
	cfg.Storage.PCAPDir = tempDir

	csvExp, err := NewCSVExporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer csvExp.Close()

	pcapExp, err := NewPCAPExporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pcapExp.Close()

	meta := &cbridge.PacketMeta{
		Timestamp:  time.Now().UTC(),
		SrcIP:      "10.0.0.1",
		DstIP:      "10.0.0.2",
		SrcPort:    80,
		DstPort:    1234,
		Protocol:   "TCP",
		PacketSize: 128,
	}
	rawPkt := make([]byte, 128)

	for i := 0; i < 250; i++ {
		csvExp.WritePacket(meta)
		pcapExp.WriteRawPacket(meta.Timestamp, rawPkt, 128)
	}
	csvExp.Close()
	pcapExp.Close()
}
