"""InfluxDB time-series exporter with asynchronous batching."""

import logging
import time
from typing import List, Optional
import scapy.all as scapy
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

from coremonitor.config import InfluxConfig
from coremonitor.models import IDSAlert, PacketMetadata
from coremonitor.storage.base import BaseExporter

logger = logging.getLogger(__name__)


class InfluxExporter(BaseExporter):
    """Batched InfluxDB v2 time-series exporter."""

    def __init__(self, config: InfluxConfig):
        self.config = config
        self.client: Optional[InfluxDBClient] = None
        self.write_api = None
        self.points_buffer: List[Point] = []
        self.last_flush = time.time()
        self.is_connected = False
        self._init_client()

    def _init_client(self) -> None:
        if not self.config.enabled:
            return
        try:
            self.client = InfluxDBClient(
                url=self.config.url,
                token=self.config.token,
                org=self.config.org,
                timeout=3000,  # 3s timeout
            )
            # Ping server
            health = self.client.health()
            if health.status == "pass":
                self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
                self.is_connected = True
                logger.info("Connected successfully to InfluxDB at %s", self.config.url)
            else:
                logger.warning("InfluxDB health check returned %s; buffering points", health.status)
                self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        except Exception as e:
            logger.warning("Could not connect to InfluxDB (%s). Points will buffer/drop gracefully.", e)
            self.is_connected = False

    def write_packet(self, raw_pkt: Optional[scapy.Packet], meta: PacketMetadata) -> None:
        if not self.config.enabled:
            return

        # Traffic point
        point = (
            Point("network_traffic")
            .tag("src_ip", meta.src_ip)
            .tag("dst_ip", meta.dst_ip)
            .tag("protocol", meta.protocol)
            .tag("service", meta.service or "unknown")
            .tag("is_broadcast", str(meta.is_broadcast).lower())
            .field("bytes", meta.packet_size)
            .field("payload_bytes", meta.payload_size)
            .field("count", 1)
            .time(meta.timestamp, WritePrecision.NS)
        )
        self.points_buffer.append(point)

        # DNS query point
        if meta.dns_query:
            dns_point = (
                Point("dns_activity")
                .tag("client_ip", meta.src_ip)
                .tag("query_name", meta.dns_query)
                .tag("qtype", meta.dns_type or "1")
                .field("query_length", len(meta.dns_query))
                .field("count", 1)
                .time(meta.timestamp, WritePrecision.NS)
            )
            self.points_buffer.append(dns_point)

        now = time.time()
        if (
            len(self.points_buffer) >= self.config.batch_size
            or (now - self.last_flush) >= self.config.flush_interval_seconds
        ):
            self.flush()

    def write_alerts(self, alerts: List[IDSAlert]) -> None:
        if not self.config.enabled or not alerts:
            return

        for alert in alerts:
            point = (
                Point("ids_alerts")
                .tag("severity", alert.severity.value)
                .tag("alert_type", alert.alert_type)
                .tag("src_ip", alert.src_ip or "unknown")
                .tag("dst_ip", alert.dst_ip or "unknown")
                .tag("protocol", alert.protocol or "unknown")
                .field("message", alert.message)
                .field("count", 1)
                .time(alert.timestamp, WritePrecision.NS)
            )
            self.points_buffer.append(point)

        self.flush()

    def flush(self) -> None:
        if not self.points_buffer:
            return

        self.last_flush = time.time()
        batch = self.points_buffer
        self.points_buffer = []

        if not self.write_api:
            # Try reconnecting lazily
            self._init_client()

        if self.write_api:
            try:
                self.write_api.write(
                    bucket=self.config.bucket,
                    org=self.config.org,
                    record=batch,
                )
            except Exception as e:
                # Keep up to 200 points in buffer to prevent unbounded RAM growth
                if len(self.points_buffer) < 200:
                    self.points_buffer.extend(batch[-100:])
                logger.debug("Failed writing batch to InfluxDB: %s", e)

    def close(self) -> None:
        self.flush()
        if self.write_api:
            try:
                self.write_api.close()
            except Exception:
                pass
            self.write_api = None
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

