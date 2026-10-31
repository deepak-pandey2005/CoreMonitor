"""Unit tests for PacketParser."""

import pytest
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

from coremonitor.parser import PacketParser


def test_parse_tcp_syn_packet():
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=54321, dport=80, flags="S")
    meta = PacketParser.parse(pkt)

    assert meta.protocol == "TCP"
    assert meta.src_ip == "192.168.1.10"
    assert meta.dst_ip == "192.168.1.20"
    assert meta.src_port == 54321
    assert meta.dst_port == 80
    assert meta.service == "HTTP"
    assert "SYN" in meta.tcp_flags
    assert meta.is_broadcast is False


def test_parse_udp_dns_packet():
    pkt = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=50000, dport=53) / DNS(rd=1, qd=DNSQR(qname="test.example.com"))
    meta = PacketParser.parse(pkt)

    assert meta.protocol == "UDP"
    assert meta.service == "DNS"
    assert meta.dns_query == "test.example.com"
    assert meta.dst_port == 53


def test_parse_icmp_packet():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    meta = PacketParser.parse(pkt)

    assert meta.protocol == "ICMP"
    assert meta.src_ip == "10.0.0.1"
    assert meta.dst_ip == "10.0.0.2"


def test_parse_broadcast():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.5", dst="192.168.1.255") / UDP(sport=68, dport=67)
    meta = PacketParser.parse(pkt)

    assert meta.is_broadcast is True
