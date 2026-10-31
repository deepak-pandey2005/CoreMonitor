"""Standard PCAP file exporter for raw offline inspection in Wireshark."""

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
import scapy.all as scapy
from scapy.utils import PcapWriter

from coremonitor.config import StorageConfig
from coremonitor.models import IDSAlert, PacketMetadata
from coremonitor.storage.base import BaseExporter


class PcapExporter(BaseExporter):
    """Writes raw captured packets to standard .pcap files."""

    def __init__(self, config: StorageConfig):
        self.config = config
        self.output_dir = Path(config.pcap_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.writer: Optional[PcapWriter] = None
        self.current_file: Optional[Path] = None
        self.last_rotation = 0.0
        self._rotate_files()

    def _rotate_files(self) -> None:
        now = time.time()
        if (
            self.writer
            and (now - self.last_rotation) < self.config.pcap_rotate_seconds
        ):
            return

        self.close()
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.current_file = self.output_dir / f"traffic_{timestamp_str}.pcap"
        self.writer = PcapWriter(str(self.current_file), append=True, sync=True)
        self.last_rotation = now

    def write_packet(self, raw_pkt: Optional[scapy.Packet], meta: PacketMetadata) -> None:
        if not self.config.pcap_enabled or raw_pkt is None:
            return
        self._rotate_files()
        if self.writer:
            try:
                self.writer.write(raw_pkt)
            except Exception:
                pass

    def write_alerts(self, alerts: List[IDSAlert]) -> None:
        # PCAP format is for raw packets only
        pass

    def flush(self) -> None:
        if self.writer:
            try:
                self.writer.flush()
            except Exception:
                pass

    def close(self) -> None:
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
            self.writer = None

