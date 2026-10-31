"""Base storage interface for CoreMonitor."""

from abc import ABC, abstractmethod
from typing import List, Optional
import scapy.all as scapy

from coremonitor.models import IDSAlert, PacketMetadata


class BaseExporter(ABC):
    """Abstract storage exporter."""

    @abstractmethod
    def write_packet(self, raw_pkt: Optional[scapy.Packet], meta: PacketMetadata) -> None:
        """Process and store a single captured packet."""
        pass

    @abstractmethod
    def write_alerts(self, alerts: List[IDSAlert]) -> None:
        """Store IDS security alerts."""
        pass

    @abstractmethod
    def flush(self) -> None:
        """Flush any pending buffers."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Clean up resources."""
        pass

