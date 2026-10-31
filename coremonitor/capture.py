"""Packet capture and live processing engine."""

import logging
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from typing import Callable, Deque, Dict, List, Optional
import scapy.all as scapy
from scapy.sendrecv import AsyncSniffer

from coremonitor.config import AppConfig
from coremonitor.ids import IDSEngine
from coremonitor.models import IDSAlert, PacketMetadata
from coremonitor.parser import PacketParser
from coremonitor.storage.base import BaseExporter
from coremonitor.storage.csv_exporter import CSVExporter
from coremonitor.storage.influx import InfluxExporter
from coremonitor.storage.pcap_exporter import PcapExporter

logger = logging.getLogger(__name__)


class LiveStats:
    """Thread-safe real-time capture metrics and summaries."""

    def __init__(self):
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts: Counter[str] = Counter()
        self.top_talkers_bytes: Counter[str] = Counter()
        self.recent_alerts: Deque[IDSAlert] = deque(maxlen=50)
        self.recent_packets: Deque[PacketMetadata] = deque(maxlen=20)
        self.rate_history: Deque[Tuple[float, int, int]] = deque(maxlen=30)  # (time, pkts, bytes)
        self.bytes_per_sec = 0.0
        self.pkts_per_sec = 0.0

    def update(self, meta: PacketMetadata, alerts: List[IDSAlert]) -> None:
        with self.lock:
            now = time.time()
            self.total_packets += 1
            self.total_bytes += meta.packet_size
            self.protocol_counts[meta.protocol] += 1
            if meta.src_ip and meta.src_ip != "unknown":
                self.top_talkers_bytes[meta.src_ip] += meta.packet_size

            self.recent_packets.append(meta)
            for alert in alerts:
                self.recent_alerts.append(alert)

            self.rate_history.append((now, 1, meta.packet_size))
            # Calculate instantaneous rate over last 2 seconds
            cutoff = now - 2.0
            while self.rate_history and self.rate_history[0][0] < cutoff:
                self.rate_history.popleft()

            if self.rate_history:
                dt = max(now - self.rate_history[0][0], 0.5)
                sec_pkts = sum(p for _, p, _ in self.rate_history)
                sec_bytes = sum(b for _, _, b in self.rate_history)
                self.pkts_per_sec = sec_pkts / dt
                self.bytes_per_sec = sec_bytes / dt


class TrafficMonitor:
    """Core monitor engine coordinating sniffing, parsing, IDS, and export."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.parser = PacketParser()
        self.ids = IDSEngine(config.ids)
        self.stats = LiveStats()

        self.exporters: List[BaseExporter] = []
        if config.storage.csv_enabled:
            self.exporters.append(CSVExporter(config.storage))
        if config.storage.pcap_enabled:
            self.exporters.append(PcapExporter(config.storage))
        if config.influxdb.enabled:
            self.exporters.append(InfluxExporter(config.influxdb))

        self.sniffer: Optional[AsyncSniffer] = None
        self.is_running = False
        self.packet_callback: Optional[Callable[[PacketMetadata, List[IDSAlert]], None]] = None

    def _process_packet(self, raw_pkt: scapy.Packet) -> None:
        try:
            meta = self.parser.parse(raw_pkt)
            alerts = self.ids.analyze(meta)
            self.stats.update(meta, alerts)

            for exp in self.exporters:
                try:
                    exp.write_packet(raw_pkt, meta)
                    if alerts:
                        exp.write_alerts(alerts)
                except Exception as e:
                    logger.debug("Exporter error: %s", e)

            if self.packet_callback:
                self.packet_callback(meta, alerts)
        except Exception as e:
            logger.debug("Packet processing error: %s", e)

    def start_live_capture(self, packet_count: int = 0) -> None:
        """Starts live packet capture on configured interface."""
        if self.is_running:
            return

        self.is_running = True
        logger.info(
            "Starting live packet capture on interface %s (BPF filter: '%s')",
            self.config.network.interface,
            self.config.network.bpf_filter,
        )

        filter_expr = self.config.network.bpf_filter or None
        self.sniffer = AsyncSniffer(
            iface=self.config.network.interface,
            prn=self._process_packet,
            filter=filter_expr,
            count=packet_count,
            store=False,
            promisc=self.config.network.promiscuous,
        )
        self.sniffer.start()

    def process_pcap_file(self, pcap_path: str) -> None:
        """Reads and analyzes an existing .pcap file for offline deep inspection."""
        logger.info("Reading offline PCAP capture from: %s", pcap_path)
        self.is_running = True
        try:
            reader = scapy.PcapReader(pcap_path)
            for pkt in reader:
                if not self.is_running:
                    break
                self._process_packet(pkt)
        finally:
            self.stop()

    def stop(self) -> None:
        """Stops the capture and flushes all exporters."""
        self.is_running = False
        if self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None

        for exp in self.exporters:
            try:
                exp.flush()
                exp.close()
            except Exception:
                pass
        logger.info("CoreMonitor stopped. All storage buffers flushed.")
