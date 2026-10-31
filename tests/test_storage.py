"""Unit tests for CSV and PCAP exporters."""

import csv
from datetime import datetime, timezone
from pathlib import Path
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from coremonitor.config import StorageConfig
from coremonitor.models import AlertSeverity, IDSAlert, PacketMetadata
from coremonitor.storage.csv_exporter import CSVExporter
from coremonitor.storage.pcap_exporter import PcapExporter


def test_csv_exporter(tmp_path):
    config = StorageConfig(
        csv_enabled=True,
        csv_dir=str(tmp_path),
        csv_rotate_seconds=3600,
    )
    exporter = CSVExporter(config)

    meta = PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=44332,
        dst_port=53,
        protocol="UDP",
        service="DNS",
        packet_size=60,
    )
    exporter.write_packet(None, meta)

    alert = IDSAlert(
        timestamp=datetime.now(timezone.utc),
        severity=AlertSeverity.HIGH,
        alert_type="TEST_ALERT",
        message="Test alert message",
        src_ip="192.168.1.100",
    )
    exporter.write_alerts([alert])
    exporter.flush()
    exporter.close()

    # Check files created
    csv_files = list(tmp_path.glob("*.csv"))
    assert len(csv_files) == 2


def test_pcap_exporter(tmp_path):
    config = StorageConfig(
        pcap_enabled=True,
        pcap_dir=str(tmp_path),
        pcap_rotate_seconds=3600,
    )
    exporter = PcapExporter(config)

    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
    meta = PacketMetadata(src_ip="10.0.0.1", dst_ip="10.0.0.2")

    exporter.write_packet(pkt, meta)
    exporter.flush()
    exporter.close()

    pcap_files = list(tmp_path.glob("*.pcap"))
    assert len(pcap_files) == 1

    # Verify readable by scapy
    read_pkts = scapy.rdpcap(str(pcap_files[0]))
    assert len(read_pkts) == 1

