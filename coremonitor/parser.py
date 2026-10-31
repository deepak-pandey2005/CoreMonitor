"""Packet parsing and metadata extraction engine."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR

from coremonitor.models import PacketMetadata

WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1337: "Backdoor-1337",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
    31337: "Back-Orifice",
}

TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


class PacketParser:
    """Parses raw Scapy packets into structured PacketMetadata."""

    @staticmethod
    def parse(packet: scapy.Packet) -> PacketMetadata:
        # Determine timestamp
        try:
            pkt_time = float(packet.time)
            ts = datetime.fromtimestamp(pkt_time, tz=timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        pkt_len = len(packet)
        src_ip = "unknown"
        dst_ip = "unknown"
        src_mac = None
        dst_mac = None
        src_port = None
        dst_port = None
        protocol = "OTHER"
        service = None
        payload_size = 0
        tcp_flags: List[str] = []
        dns_query = None
        dns_type = None
        is_broadcast = False

        # Layer 2 MAC addresses
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            if dst_mac == "ff:ff:ff:ff:ff:ff":
                is_broadcast = True

        # Layer 3 IP / IPv6 / ARP
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "IPv4"
            if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
                is_broadcast = True
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            protocol = "IPv6"
            if dst_ip.startswith("ff02:"):
                is_broadcast = True
        elif packet.haslayer(ARP):
            protocol = "ARP"
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            src_mac = packet[ARP].hwsrc
            dst_mac = packet[ARP].hwdst
            is_broadcast = packet[ARP].op == 1  # who-has request is broadcast

        # Layer 4 TCP / UDP / ICMP
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            raw_flags = str(packet[TCP].flags)
            tcp_flags = [TCP_FLAG_NAMES[f] for f in raw_flags if f in TCP_FLAG_NAMES]
            if packet.haslayer(scapy.Raw):
                payload_size = len(packet[scapy.Raw].load)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
            if packet.haslayer(scapy.Raw):
                payload_size = len(packet[scapy.Raw].load)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            if packet.haslayer(scapy.Raw):
                payload_size = len(packet[scapy.Raw].load)

        # Application Layer checks
        if packet.haslayer(DNS):
            service = "DNS"
            try:
                if packet.haslayer(DNSQR) and packet[DNS].qd:
                    qname = packet[DNSQR].qname
                    if isinstance(qname, bytes):
                        dns_query = qname.decode("utf-8", errors="ignore").rstrip(".")
                    else:
                        dns_query = str(qname).rstrip(".")
                    dns_type = str(packet[DNSQR].qtype)
            except Exception:
                pass

        if not service:
            if dst_port in WELL_KNOWN_PORTS:
                service = WELL_KNOWN_PORTS[dst_port]
            elif src_port in WELL_KNOWN_PORTS:
                service = WELL_KNOWN_PORTS[src_port]

        return PacketMetadata(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            service=service,
            packet_size=pkt_len,
            payload_size=payload_size,
            tcp_flags=tcp_flags,
            dns_query=dns_query,
            dns_type=dns_type,
            is_broadcast=is_broadcast,
        )
