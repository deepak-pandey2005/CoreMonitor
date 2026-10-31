"""Synthetic network traffic generator for testing CoreMonitor IDS & exporters."""

import argparse
import time
from typing import List
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether


def generate_scenario_packets() -> List[scapy.Packet]:
    packets: List[scapy.Packet] = []

    print("[*] Generating benign traffic (HTTP, HTTPS, DNS, NTP)...")
    # Benign web traffic
    packets.append(Ether() / IP(src="192.168.1.105", dst="142.250.190.46") / TCP(sport=51234, dport=443, flags="PA") / b"TLS Application Data payload")
    packets.append(Ether() / IP(src="142.250.190.46", dst="192.168.1.105") / TCP(sport=443, dport=51234, flags="A"))
    packets.append(Ether() / IP(src="192.168.1.105", dst="93.184.216.34") / TCP(sport=51235, dport=80, flags="PA") / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")

    # Benign DNS query
    packets.append(Ether() / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com")))

    print("[*] Generating Port Scan (SYN scan probing 20 ports)...")
    attacker_ip = "192.168.1.200"
    for port in range(20, 40):
        packets.append(Ether() / IP(src=attacker_ip, dst="192.168.1.50") / TCP(sport=40000 + port, dport=port, flags="S"))

    print("[*] Generating Stealth Scans (Xmas scan & Null scan)...")
    # Xmas scan (FIN, PSH, URG)
    packets.append(Ether() / IP(src="192.168.1.205", dst="192.168.1.50") / TCP(sport=45000, dport=80, flags="FPU"))
    # Null scan (no flags)
    packets.append(Ether() / IP(src="192.168.1.206", dst="192.168.1.50") / TCP(sport=45001, dport=443, flags=0))

    print("[*] Generating Suspicious Port Activity (Telnet & Metasploit C2)...")
    # Telnet cleartext connection
    packets.append(Ether() / IP(src="192.168.1.120", dst="192.168.1.1") / TCP(sport=52000, dport=23, flags="PA") / b"admin:secret_password\r\n")
    # Metasploit reverse shell probe (port 4444)
    packets.append(Ether() / IP(src="192.168.1.130", dst="10.0.0.5") / TCP(sport=53000, dport=4444, flags="S"))

    print("[*] Generating Threat Intelligence match (Blacklisted IP)...")
    packets.append(Ether() / IP(src="198.51.100.23", dst="192.168.1.50") / TCP(sport=443, dport=55123, flags="PA") / b"Malicious payload")

    print("[*] Generating Anomalous DNS Tunneling query...")
    tunnel_subdomain = "v1-0a4fbc89e31d994e77a2810cd04481bc90aef.exfil-data.tunnel.attacker-domain.xyz"
    packets.append(Ether() / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=54322, dport=53) / DNS(rd=1, qd=DNSQR(qname=tunnel_subdomain)))

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
