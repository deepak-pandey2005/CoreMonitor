"""Configuration loader and settings validation."""

from pathlib import Path
from typing import Dict, List, Optional
import yaml
from pydantic import BaseModel, Field


class NetworkConfig(BaseModel):
    interface: str = "wlan0"
    bpf_filter: str = ""
    promiscuous: bool = True
    snaplen: int = 65535


class StorageConfig(BaseModel):
    pcap_enabled: bool = True
    pcap_dir: str = "captures"
    pcap_rotate_seconds: int = 3600
    csv_enabled: bool = True
    csv_dir: str = "captures"
    csv_rotate_seconds: int = 3600


class InfluxConfig(BaseModel):
    enabled: bool = True
    url: str = "http://localhost:8086"
    token: str = "coremonitor-super-secret-auth-token"
    org: str = "coremonitor-org"
    bucket: str = "network_metrics"
    batch_size: int = 50
    flush_interval_seconds: int = 2


class IDSConfig(BaseModel):
    enabled: bool = True
    port_scan_threshold: int = 15
    port_scan_window_seconds: int = 10
    syn_flood_threshold: int = 100
    syn_flood_window_seconds: int = 2
    bandwidth_spike_bytes_per_sec: int = 10_000_000  # 10 MB/s
    bandwidth_window_seconds: int = 2
    dns_tunnel_anomaly_length: int = 60
    suspicious_ports: Dict[int, str] = Field(
        default_factory=lambda: {
            21: "FTP (Insecure Cleartext Protocol)",
            23: "Telnet (Insecure Cleartext Protocol)",
            4444: "Metasploit Default C2 Listener",
            1337: "Common Hacker / Backdoor Port",
            31337: "Back Orifice Trojan Port",
            6667: "IRC (Historical Botnet C2)",
            5555: "Android ADB Exposed / Trojan Port",
        }
    )
    blacklist_ips: List[str] = Field(
        default_factory=lambda: [
            "198.51.100.23",
            "203.0.113.50",
            "185.220.101.5",
        ]
    )


class AppConfig(BaseModel):
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    influxdb: InfluxConfig = Field(default_factory=InfluxConfig)
    ids: IDSConfig = Field(default_factory=IDSConfig)
    live_dashboard: bool = True

    @classmethod
    def load_from_yaml(cls, path: str = "config.yaml") -> "AppConfig":
        file_path = Path(path)
        if not file_path.exists():
            return cls()
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)
