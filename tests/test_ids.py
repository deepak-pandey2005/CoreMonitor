"""Unit tests for IDSEngine detection rules."""

from datetime import datetime, timezone
import pytest

from coremonitor.config import IDSConfig
from coremonitor.ids import IDSEngine
from coremonitor.models import AlertSeverity, PacketMetadata


@pytest.fixture
def ids_engine():
    config = IDSConfig(
        enabled=True,
        port_scan_threshold=5,
        port_scan_window_seconds=10,
        syn_flood_threshold=10,
        dns_tunnel_anomaly_length=40,
        blacklist_ips=["198.51.100.99"],
    )
    return IDSEngine(config)


def test_blacklisted_ip_detection(ids_engine):
    meta = PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        src_ip="198.51.100.99",
        dst_ip="192.168.1.10",
        protocol="TCP",
        tcp_flags=["ACK"],
    )
    alerts = ids_engine.analyze(meta)
    assert any(a.alert_type == "BLACKLISTED_IP" for a in alerts)
    assert any(a.severity == AlertSeverity.CRITICAL for a in alerts)


def test_suspicious_port_detection(ids_engine):
    meta = PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        dst_port=23,  # Telnet
        protocol="TCP",
    )
    alerts = ids_engine.analyze(meta)
    assert any(a.alert_type == "SUSPICIOUS_PORT" for a in alerts)


def test_xmas_scan_detection(ids_engine):
    meta = PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.88",
        dst_ip="192.168.1.1",
        dst_port=80,
        protocol="TCP",
        tcp_flags=["FIN", "PSH", "URG"],
    )
    alerts = ids_engine.analyze(meta)
    assert any(a.alert_type == "XMAS_SCAN" for a in alerts)


def test_null_scan_detection(ids_engine):
    meta = PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.88",
        dst_ip="192.168.1.1",
        dst_port=80,
        protocol="TCP",
        tcp_flags=[],
    )
    alerts = ids_engine.analyze(meta)
    assert any(a.alert_type == "NULL_SCAN" for a in alerts)


def test_port_scan_syn_threshold(ids_engine):
    src = "192.168.1.99"
    triggered = False
    for port in range(100, 110):
        meta = PacketMetadata(
            timestamp=datetime.now(timezone.utc),
            src_ip=src,
            dst_ip="192.168.1.1",
            dst_port=port,
            protocol="TCP",
            tcp_flags=["SYN"],
        )
        alerts = ids_engine.analyze(meta)
        if any(a.alert_type == "PORT_SCAN_SYN" for a in alerts):
            triggered = True
            break
    assert triggered is True


def test_dns_tunneling_detection(ids_engine):
    meta = PacketMetadata(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.15",
        dst_ip="8.8.8.8",
        protocol="UDP",
        dns_query="superlongexfiltrateddata1234567890abcdef.suspiciousdomain.xyz",
    )
    alerts = ids_engine.analyze(meta)
    assert any(a.alert_type == "DNS_TUNNEL_ANOMALY" for a in alerts)
