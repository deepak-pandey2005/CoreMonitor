"""Lightweight Intrusion Detection System (IDS) and anomaly detection engine."""

import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Set, Tuple

from coremonitor.config import IDSConfig
from coremonitor.models import AlertSeverity, IDSAlert, PacketMetadata


class IDSEngine:
    """Stateful lightweight IDS analyzing stream of PacketMetadata."""

    def __init__(self, config: IDSConfig):
        self.config = config

        # Sliding window state for Port Scans: src_ip -> deque of (timestamp, dst_port)
        self.port_scan_tracker: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)

        # Sliding window state for SYN Floods: src_ip -> deque of timestamp
        self.syn_flood_tracker: Dict[str, Deque[float]] = defaultdict(deque)

        # Sliding window state for ICMP Floods: src_ip -> deque of timestamp
        self.icmp_flood_tracker: Dict[str, Deque[float]] = defaultdict(deque)

        # Sliding window state for Bandwidth Spikes: src_ip -> deque of (timestamp, byte_count)
        self.bandwidth_tracker: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)

        # Alert cooldown to avoid alert storm: (alert_type, src_ip) -> last_alert_time
        self.alert_cooldowns: Dict[Tuple[str, str], float] = {}
        self.cooldown_period_seconds = 10.0

        # Maintain set of blacklisted IPs for O(1) lookup
        self.blacklisted_ips: Set[str] = set(self.config.blacklist_ips)

    def _should_suppress_alert(self, alert_type: str, key: str, now: float) -> bool:
        cache_key = (alert_type, key)
        last_time = self.alert_cooldowns.get(cache_key)
        if last_time and (now - last_time) < self.cooldown_period_seconds:
            return True
        self.alert_cooldowns[cache_key] = now
        return False

    def analyze(self, meta: PacketMetadata) -> List[IDSAlert]:
        """Analyze a single packet metadata and return any triggered alerts."""
        if not self.config.enabled:
            return []

        alerts: List[IDSAlert] = []
        now = meta.timestamp.timestamp() if meta.timestamp else time.time()

        # 1. Blacklist / Threat Feed Matching
        if meta.src_ip in self.blacklisted_ips:
            if not self._should_suppress_alert("BLACKLISTED_IP", meta.src_ip, now):
                alerts.append(
                    IDSAlert(
                        timestamp=meta.timestamp,
                        severity=AlertSeverity.CRITICAL,
                        alert_type="BLACKLISTED_IP",
                        message=f"Traffic detected from known malicious/blacklisted IP: {meta.src_ip}",
                        src_ip=meta.src_ip,
                        dst_ip=meta.dst_ip,
                        src_port=meta.src_port,
                        dst_port=meta.dst_port,
                        protocol=meta.protocol,
                        details={"threat_ip": meta.src_ip, "direction": "inbound"},
                    )
                )

        if meta.dst_ip in self.blacklisted_ips:
            if not self._should_suppress_alert("BLACKLISTED_IP", meta.dst_ip, now):
                alerts.append(
                    IDSAlert(
                        timestamp=meta.timestamp,
                        severity=AlertSeverity.CRITICAL,
                        alert_type="BLACKLISTED_IP",
                        message=f"Outbound connection attempt to blacklisted IP: {meta.dst_ip}",
                        src_ip=meta.src_ip,
                        dst_ip=meta.dst_ip,
                        src_port=meta.src_port,
                        dst_port=meta.dst_port,
                        protocol=meta.protocol,
                        details={"threat_ip": meta.dst_ip, "direction": "outbound"},
                    )
                )

        # 2. Suspicious Ports Check
        target_port = meta.dst_port
        if target_port and target_port in self.config.suspicious_ports:
            port_desc = self.config.suspicious_ports[target_port]
            suppress_key = f"{meta.src_ip}:{target_port}"
            if not self._should_suppress_alert("SUSPICIOUS_PORT", suppress_key, now):
                severity = (
                    AlertSeverity.HIGH
                    if target_port in [4444, 1337, 31337, 5555]
                    else AlertSeverity.MEDIUM
                )
                alerts.append(
                    IDSAlert(
                        timestamp=meta.timestamp,
                        severity=severity,
                        alert_type="SUSPICIOUS_PORT",
                        message=f"Connection targeting suspicious port {target_port} ({port_desc}) from {meta.src_ip}",
                        src_ip=meta.src_ip,
                        dst_ip=meta.dst_ip,
                        src_port=meta.src_port,
                        dst_port=meta.dst_port,
                        protocol=meta.protocol,
                        details={"port": target_port, "description": port_desc},
                    )
                )

        # 3. Stealth Scans (Xmas, Null, FIN scans)
        if meta.protocol == "TCP":
            flags = set(meta.tcp_flags)
            # Xmas scan: FIN, PSH, URG all set
            if {"FIN", "PSH", "URG"}.issubset(flags):
                if not self._should_suppress_alert("XMAS_SCAN", meta.src_ip, now):
                    alerts.append(
                        IDSAlert(
                            timestamp=meta.timestamp,
                            severity=AlertSeverity.HIGH,
                            alert_type="XMAS_SCAN",
                            message=f"TCP Xmas stealth scan packet detected from {meta.src_ip}",
                            src_ip=meta.src_ip,
                            dst_ip=meta.dst_ip,
                            src_port=meta.src_port,
                            dst_port=meta.dst_port,
                            protocol="TCP",
                            details={"flags": list(flags)},
                        )
                    )
            # Null scan: TCP flags are empty
            elif len(flags) == 0:
                if not self._should_suppress_alert("NULL_SCAN", meta.src_ip, now):
                    alerts.append(
                        IDSAlert(
                            timestamp=meta.timestamp,
                            severity=AlertSeverity.HIGH,
                            alert_type="NULL_SCAN",
                            message=f"TCP Null stealth scan packet detected from {meta.src_ip}",
                            src_ip=meta.src_ip,
                            dst_ip=meta.dst_ip,
                            src_port=meta.src_port,
                            dst_port=meta.dst_port,
                            protocol="TCP",
                            details={"flags": []},
                        )
                    )
            # FIN scan: only FIN is set
            elif flags == {"FIN"}:
                if not self._should_suppress_alert("FIN_SCAN", meta.src_ip, now):
                    alerts.append(
                        IDSAlert(
                            timestamp=meta.timestamp,
                            severity=AlertSeverity.HIGH,
                            alert_type="FIN_SCAN",
                            message=f"TCP FIN stealth scan packet detected from {meta.src_ip}",
                            src_ip=meta.src_ip,
                            dst_ip=meta.dst_ip,
                            src_port=meta.src_port,
                            dst_port=meta.dst_port,
                            protocol="TCP",
                            details={"flags": ["FIN"]},
                        )
                    )

            # 4. Port Scan (SYN scan)
            if "SYN" in flags and "ACK" not in flags and meta.dst_port:
                ports_queue = self.port_scan_tracker[meta.src_ip]
                ports_queue.append((now, meta.dst_port))
                # Purge older than window
                cutoff = now - self.config.port_scan_window_seconds
                while ports_queue and ports_queue[0][0] < cutoff:
                    ports_queue.popleft()

                distinct_ports = {p for _, p in ports_queue}
                if len(distinct_ports) >= self.config.port_scan_threshold:
                    if not self._should_suppress_alert("PORT_SCAN_SYN", meta.src_ip, now):
                        alerts.append(
                            IDSAlert(
                                timestamp=meta.timestamp,
                                severity=AlertSeverity.HIGH,
                                alert_type="PORT_SCAN_SYN",
                                message=f"Port scan detected from {meta.src_ip}: {len(distinct_ports)} distinct ports probed in {self.config.port_scan_window_seconds}s",
                                src_ip=meta.src_ip,
                                dst_ip=meta.dst_ip,
                                src_port=meta.src_port,
                                dst_port=meta.dst_port,
                                protocol="TCP",
                                details={
                                    "probed_ports_count": len(distinct_ports),
                                    "sample_ports": list(distinct_ports)[:10],
                                },
                            )
                        )

            # 5. SYN Flood
            if "SYN" in flags and "ACK" not in flags:
                syn_queue = self.syn_flood_tracker[meta.src_ip]
                syn_queue.append(now)
                cutoff = now - self.config.syn_flood_window_seconds
                while syn_queue and syn_queue[0] < cutoff:
                    syn_queue.popleft()

                if len(syn_queue) >= self.config.syn_flood_threshold:
                    if not self._should_suppress_alert("SYN_FLOOD", meta.src_ip, now):
                        alerts.append(
                            IDSAlert(
                                timestamp=meta.timestamp,
                                severity=AlertSeverity.CRITICAL,
                                alert_type="SYN_FLOOD",
                                message=f"TCP SYN flood detected from {meta.src_ip}: {len(syn_queue)} SYNs in {self.config.syn_flood_window_seconds}s",
                                src_ip=meta.src_ip,
                                dst_ip=meta.dst_ip,
                                src_port=meta.src_port,
                                dst_port=meta.dst_port,
                                protocol="TCP",
                                details={"syn_rate_per_sec": len(syn_queue) / max(self.config.syn_flood_window_seconds, 1)},
                            )
                        )

        # 6. ICMP Flood (Ping Flood)
        if meta.protocol == "ICMP":
            icmp_queue = self.icmp_flood_tracker[meta.src_ip]
            icmp_queue.append(now)
            cutoff = now - 2.0  # 2 second window
            while icmp_queue and icmp_queue[0] < cutoff:
                icmp_queue.popleft()

            if len(icmp_queue) >= 50:  # > 25 pings / sec
                if not self._should_suppress_alert("ICMP_FLOOD", meta.src_ip, now):
                    alerts.append(
                        IDSAlert(
                            timestamp=meta.timestamp,
                            severity=AlertSeverity.HIGH,
                            alert_type="ICMP_FLOOD",
                            message=f"ICMP ping flood detected from {meta.src_ip} ({len(icmp_queue)} packets in 2s)",
                            src_ip=meta.src_ip,
                            dst_ip=meta.dst_ip,
                            protocol="ICMP",
                            details={"icmp_count": len(icmp_queue)},
                        )
                    )

        # 7. Bandwidth Spike / Traffic Flood
        bw_queue = self.bandwidth_tracker[meta.src_ip]
        bw_queue.append((now, meta.packet_size))
        cutoff = now - self.config.bandwidth_window_seconds
        while bw_queue and bw_queue[0][0] < cutoff:
            bw_queue.popleft()

        total_bytes = sum(b for _, b in bw_queue)
        bytes_per_sec = total_bytes / max(self.config.bandwidth_window_seconds, 1)
        if bytes_per_sec >= self.config.bandwidth_spike_bytes_per_sec:
            if not self._should_suppress_alert("BANDWIDTH_SPIKE", meta.src_ip, now):
                rate_mb = bytes_per_sec / (1024 * 1024)
                alerts.append(
                    IDSAlert(
                        timestamp=meta.timestamp,
                        severity=AlertSeverity.MEDIUM,
                        alert_type="BANDWIDTH_SPIKE",
                        message=f"Bandwidth spike detected from {meta.src_ip}: {rate_mb:.2f} MB/s",
                        src_ip=meta.src_ip,
                        dst_ip=meta.dst_ip,
                        src_port=meta.src_port,
                        dst_port=meta.dst_port,
                        protocol=meta.protocol,
                        details={"bytes_per_sec": bytes_per_sec, "rate_mb_s": round(rate_mb, 2)},
                    )
                )

        # 8. DNS Tunneling Anomaly
        if meta.dns_query:
            query_len = len(meta.dns_query)
            if query_len > self.config.dns_tunnel_anomaly_length:
                if not self._should_suppress_alert("DNS_TUNNEL_ANOMALY", meta.dns_query, now):
                    alerts.append(
                        IDSAlert(
                            timestamp=meta.timestamp,
                            severity=AlertSeverity.HIGH,
                            alert_type="DNS_TUNNEL_ANOMALY",
                            message=f"Abnormally long DNS query detected ({query_len} chars): potential DNS tunneling or exfiltration",
                            src_ip=meta.src_ip,
                            dst_ip=meta.dst_ip,
                            protocol="DNS",
                            details={"dns_query": meta.dns_query, "query_length": query_len},
                        )
                    )

        return alerts

