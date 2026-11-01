#!/usr/bin/env python3
"""Synthetic network traffic generator for testing CoreMonitor IDS & exporters."""

import argparse
from typing import List
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP


def generate_scenario_packets() -> List[scapy.Packet]:
    packets: List[scapy.Packet] = []

    print("[*] Generating benign traffic (HTTP, HTTPS, DNS)...")
    packets.append(Ether() / IP(src="192.168.1.105", dst="142.250.190.46") / TCP(sport=51234, dport=443, flags="PA") / b"TLS Application Data payload")
    packets.append(Ether() / IP(src="142.250.190.46", dst="192.168.1.105") / TCP(sport=443, dport=51234, flags="A"))

    # Synthetic TLS Client Hello with SNI "github.com"
    tls_payload = (
        b"\x16\x03\x01\x00\x80\x01\x00\x00\x7c\x03\x03"
        + b"\x00" * 32  # random
        + b"\x00"       # session ID len
        + b"\x00\x02\xc0\x2f"  # cipher suites
        + b"\x01\x00"   # compression
        + b"\x00\x13"   # ext len
        + b"\x00\x00\x00\x0f\x00\x0d\x00\x00\x0a" + b"github.com"
    )
    packets.append(Ether() / IP(src="192.168.1.105", dst="140.82.112.4") / TCP(sport=51238, dport=443, flags="PA") / tls_payload)
    packets.append(Ether() / IP(src="192.168.1.105", dst="93.184.216.34") / TCP(sport=51235, dport=80, flags="PA") / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n\r\n")
    packets.append(Ether() / IP(src="192.168.1.105", dst="93.184.216.34") / TCP(sport=51236, dport=80, flags="PA") / b"POST /api/v1/auth HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: curl/8.2.1\r\n\r\n")
    packets.append(Ether() / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com")))

    print("[*] Generating Port Scan (SYN scan probing 20 ports)...")
    attacker_ip = "192.168.1.200"
    for port in range(20, 40):
        packets.append(Ether() / IP(src=attacker_ip, dst="192.168.1.50") / TCP(sport=40000 + port, dport=port, flags="S"))

    print("[*] Generating Stealth Scans (Xmas scan & Null scan)...")
    packets.append(Ether() / IP(src="192.168.1.205", dst="192.168.1.50") / TCP(sport=45000, dport=80, flags="FPU"))
    packets.append(Ether() / IP(src="192.168.1.206", dst="192.168.1.50") / TCP(sport=45001, dport=443, flags=0))

    print("[*] Generating Suspicious Port Activity (Telnet & Metasploit C2)...")
    packets.append(Ether() / IP(src="192.168.1.120", dst="192.168.1.1") / TCP(sport=52000, dport=23, flags="PA") / b"admin:secret_password\r\n")
    packets.append(Ether() / IP(src="192.168.1.130", dst="10.0.0.5") / TCP(sport=53000, dport=4444, flags="S"))

    print("[*] Generating Threat Intelligence match (Blacklisted IP)...")
    packets.append(Ether() / IP(src="198.51.100.23", dst="192.168.1.50") / TCP(sport=443, dport=55123, flags="PA") / b"Malicious payload")

    print("[*] Generating Anomalous DNS Tunneling query...")
    tunnel_subdomain = "v1-0a4fbc89e31d994e77a2810cd04481bc90aef.exfil-data.tunnel.attacker-domain.xyz"
    packets.append(Ether() / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=54322, dport=53) / DNS(rd=1, qd=DNSQR(qname=tunnel_subdomain)))

    print("[*] Generating ARP Poisoning & Spoofing simulation...")
    # Legitimate Gateway ARP announcement
    packets.append(Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(op="is-at", hwsrc="00:11:22:33:44:55", psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1"))
    # Rogue attacker claiming Gateway IP with rogue MAC
    packets.append(Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / ARP(op="is-at", hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.50"))

    print("[*] Generating ICMP Ping burst...")
    for _ in range(55):
        packets.append(Ether() / IP(src="192.168.1.220", dst="192.168.1.1") / ICMP())

    return packets


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic traffic & attacks PCAP.")
    parser.add_argument("--output", "-o", default="captures/sample_traffic.pcap", help="Output .pcap file path")
    args = parser.parse_args()

    pkts = generate_scenario_packets()
    scapy.wrpcap(args.output, pkts)
    print(f"\n[+] Successfully generated {len(pkts)} packets into: {args.output}")


if __name__ == "__main__":
    main()
