#include "cmonitor/parser.h"
#include <arpa/inet.h>
#include <assert.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

void test_parse_tcp_syn() {
    uint8_t buffer[128] = {0};
    struct ether_header *eth = (struct ether_header*)buffer;
    eth->ether_type = htons(ETHERTYPE_IP);
    memset(eth->ether_shost, 0x11, 6);
    memset(eth->ether_dhost, 0x22, 6);

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
    ip->ihl = 5;
    ip->version = 4;
    ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, "192.168.1.50", &ip->saddr);
    inet_pton(AF_INET, "10.0.0.1", &ip->daddr);

    struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ether_header) + 20);
    tcp->source = htons(54321);
    tcp->dest = htons(80);
    tcp->doff = 5;
    buffer[sizeof(struct ether_header) + 20 + 13] = 0x02; // SYN flag

    cmonitor_packet_meta_t meta;
    int res = cmonitor_parse_packet(buffer, sizeof(buffer), sizeof(buffer), 1000, 500, &meta);
    assert(res == 0);
    assert(strcmp(meta.protocol, "TCP") == 0);
    assert(strcmp(meta.src_ip, "192.168.1.50") == 0);
    assert(strcmp(meta.dst_ip, "10.0.0.1") == 0);
    assert(meta.src_port == 54321);
    assert(meta.dst_port == 80);
    assert(meta.tcp_flags & CMONITOR_TCP_SYN);
    assert(strcmp(meta.service, "HTTP") == 0);
    printf("✓ test_parse_tcp_syn passed\n");
}

void test_parse_udp_dns() {
    uint8_t buffer[256] = {0};
    struct ether_header *eth = (struct ether_header*)buffer;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
    ip->ihl = 5;
    ip->version = 4;
    ip->protocol = IPPROTO_UDP;
    inet_pton(AF_INET, "192.168.1.100", &ip->saddr);
    inet_pton(AF_INET, "8.8.8.8", &ip->daddr);

    struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ether_header) + 20);
    udp->source = htons(45000);
    udp->dest = htons(53);

    // DNS Header (12 bytes)
    uint8_t *dns = buffer + sizeof(struct ether_header) + 20 + sizeof(struct udphdr);
    // DNS Question: 6google3com0
    size_t q_offset = 12;
    dns[q_offset++] = 6;
    memcpy(dns + q_offset, "google", 6);
    q_offset += 6;
    dns[q_offset++] = 3;
    memcpy(dns + q_offset, "com", 3);
    q_offset += 3;
    dns[q_offset++] = 0; // null byte
    dns[q_offset++] = 0; // QTYPE high
    dns[q_offset++] = 1; // QTYPE A

    size_t total_len = sizeof(struct ether_header) + 20 + sizeof(struct udphdr) + q_offset + 2;

    cmonitor_packet_meta_t meta;
    int res = cmonitor_parse_packet(buffer, total_len, total_len, 2000, 0, &meta);
    assert(res == 0);
    assert(strcmp(meta.protocol, "UDP") == 0);
    assert(meta.dst_port == 53);
    assert(strcmp(meta.service, "DNS") == 0);
    assert(strcmp(meta.dns_query, "google.com") == 0);
    printf("✓ test_parse_udp_dns passed\n");
}

int main() {
    printf("Running C Core Parser Tests...\n");
    test_parse_tcp_syn();
    test_parse_udp_dns();
    printf("All C Parser tests passed successfully!\n");
    return 0;
}
