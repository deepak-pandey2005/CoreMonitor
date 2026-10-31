"""CSV file exporter for packet metadata and security alerts."""

import csv
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
import scapy.all as scapy

from coremonitor.config import StorageConfig
from coremonitor.models import IDSAlert, PacketMetadata
from coremonitor.storage.base import BaseExporter

PACKET_CSV_HEADERS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "service",
    "packet_size",
    "payload_size",
    "tcp_flags",
    "dns_query",
    "dns_type",
    "src_mac",
    "dst_mac",
]

ALERT_CSV_HEADERS = [
    "timestamp",
    "severity",
    "alert_type",
    "message",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "details",
]


class CSVExporter(BaseExporter):
    """Writes packet metadata and IDS alerts to structured CSV files."""

    def __init__(self, config: StorageConfig):
        self.config = config
        self.output_dir = Path(config.csv_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.packet_file = None
        self.packet_writer = None
        self.alert_file = None
        self.alert_writer = None

        self.last_rotation = 0.0
        self._rotate_files()

    def _rotate_files(self) -> None:
        now = time.time()
        if (
            self.packet_file
            and (now - self.last_rotation) < self.config.csv_rotate_seconds
        ):
            return

        self.close()
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        pkt_path = self.output_dir / f"traffic_{timestamp_str}.csv"
        pkt_exists = pkt_path.exists()
        self.packet_file = open(pkt_path, "a", newline="", encoding="utf-8")
        self.packet_writer = csv.DictWriter(self.packet_file, fieldnames=PACKET_CSV_HEADERS)
        if not pkt_exists:
            self.packet_writer.writeheader()

        alert_path = self.output_dir / f"alerts_{timestamp_str}.csv"
        alert_exists = alert_path.exists()
        self.alert_file = open(alert_path, "a", newline="", encoding="utf-8")
        self.alert_writer = csv.DictWriter(self.alert_file, fieldnames=ALERT_CSV_HEADERS)
        if not alert_exists:
            self.alert_writer.writeheader()

        self.last_rotation = now

    def write_packet(self, raw_pkt: Optional[scapy.Packet], meta: PacketMetadata) -> None:
        if not self.config.csv_enabled:
            return
        self._rotate_files()
        if self.packet_writer:
            self.packet_writer.writerow(meta.to_csv_dict())

    def write_alerts(self, alerts: List[IDSAlert]) -> None:
        if not self.config.csv_enabled or not alerts:
            return
        self._rotate_files()
        if self.alert_writer:
            for alert in alerts:
                self.alert_writer.writerow(
                    {
                        "timestamp": alert.timestamp.isoformat(),
                        "severity": alert.severity.value,
                        "alert_type": alert.alert_type,
                        "message": alert.message,
                        "src_ip": alert.src_ip or "",
                        "dst_ip": alert.dst_ip or "",
                        "src_port": alert.src_port or "",
                        "dst_port": alert.dst_port or "",
                        "protocol": alert.protocol or "",
                        "details": str(alert.details),
                    }
                )

    def flush(self) -> None:
        if self.packet_file:
            self.packet_file.flush()
        if self.alert_file:
            self.alert_file.flush()

    def close(self) -> None:
        if self.packet_file:
            try:
                self.packet_file.close()
            except Exception:
                pass
            self.packet_file = None
            self.packet_writer = None

        if self.alert_file:
            try:
                self.alert_file.close()
            except Exception:
                pass
            self.alert_file = None
            self.alert_writer = None
