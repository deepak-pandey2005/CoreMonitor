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

void test_parse_tls_sni() {
    uint8_t buffer[256] = {0};
    struct ether_header *eth = (struct ether_header*)buffer;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
    ip->ihl = 5;
    ip->version = 4;
    ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, "192.168.1.100", &ip->saddr);
    inet_pton(AF_INET, "140.82.112.4", &ip->daddr);

    struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ether_header) + 20);
    tcp->source = htons(52345);
    tcp->dest = htons(443);
    tcp->doff = 5;

    uint8_t *tls = buffer + sizeof(struct ether_header) + 20 + 20;
    size_t offset = 0;
    tls[offset++] = 0x16; // Handshake record
    tls[offset++] = 0x03; // TLS 1.0
    tls[offset++] = 0x01;
    tls[offset++] = 0x00; // Length high
    tls[offset++] = 0x80; // Length low (dummy)
    tls[offset++] = 0x01; // Client Hello
    tls[offset++] = 0x00; // Handshake len high
    tls[offset++] = 0x00;
    tls[offset++] = 0x7c; // Handshake len low
    tls[offset++] = 0x03; // Client version TLS 1.2
    tls[offset++] = 0x03;

    // Random (32 bytes)
    offset += 32;

    // Session ID length = 0
    tls[offset++] = 0x00;

    // Cipher suites length = 2 (1 suite)
    tls[offset++] = 0x00;
    tls[offset++] = 0x02;
    tls[offset++] = 0xc0;
    tls[offset++] = 0x2f;

    // Compression methods length = 1
    tls[offset++] = 0x01;
    tls[offset++] = 0x00; // null compression

    // Extensions length = 19
    tls[offset++] = 0x00;
    tls[offset++] = 0x13;

    // Extension 0x0000 (server_name)
    tls[offset++] = 0x00;
    tls[offset++] = 0x00;
    // Extension length = 15
    tls[offset++] = 0x00;
    tls[offset++] = 0x0f;
    // Server name list length = 13
    tls[offset++] = 0x00;
    tls[offset++] = 0x0d;
    // Name type = 0 (host_name)
    tls[offset++] = 0x00;
    // Host name length = 10 ("github.com")
    tls[offset++] = 0x00;
    tls[offset++] = 0x0a;
    memcpy(tls + offset, "github.com", 10);
    offset += 10;

    size_t total_len = sizeof(struct ether_header) + 20 + 20 + offset;

    cmonitor_packet_meta_t meta;
    int res = cmonitor_parse_packet(buffer, total_len, total_len, 3000, 0, &meta);
    assert(res == 0);
    assert(strcmp(meta.protocol, "TCP") == 0);
    assert(meta.dst_port == 443);
    assert(strcmp(meta.service, "HTTPS") == 0);
    assert(strcmp(meta.tls_sni, "github.com") == 0);
    printf("✓ test_parse_tls_sni passed (Extracted SNI: %s)\n", meta.tls_sni);
}

int main() {
    printf("Running C Core Parser Tests...\n");
    test_parse_tcp_syn();
    test_parse_udp_dns();
    test_parse_tls_sni();
    printf("All C Parser tests passed successfully!\n");
    return 0;
}
