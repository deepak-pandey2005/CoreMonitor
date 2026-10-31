"""Data models for CoreMonitor."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PacketMetadata(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str = "unknown"
    dst_ip: str = "unknown"
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "OTHER"
    service: Optional[str] = None
    packet_size: int = 0
    payload_size: int = 0
    tcp_flags: List[str] = Field(default_factory=list)
    dns_query: Optional[str] = None
    dns_type: Optional[str] = None
    is_broadcast: bool = False

    def to_csv_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port or "",
            "dst_port": self.dst_port or "",
            "protocol": self.protocol,
            "service": self.service or "",
            "packet_size": self.packet_size,
            "payload_size": self.payload_size,
            "tcp_flags": ",".join(self.tcp_flags),
            "dns_query": self.dns_query or "",
            "dns_type": self.dns_type or "",
            "src_mac": self.src_mac or "",
            "dst_mac": self.dst_mac or "",
        }


class IDSAlert(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AlertSeverity = AlertSeverity.MEDIUM
    alert_type: str
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

