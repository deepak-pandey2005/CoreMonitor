#include "cmonitor/parser.h"
#include <arpa/inet.h>
#include <assert.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
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

static void test_parse_http_request() {
    uint8_t buffer[512] = {0};
    struct ether_header *eth = (struct ether_header*)buffer;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
    ip->ihl = 5;
    ip->version = 4;
    ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, "10.0.0.15", &ip->saddr);
    inet_pton(AF_INET, "192.168.1.80", &ip->daddr);

    struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ether_header) + 20);
    tcp->source = htons(54321);
    tcp->dest = htons(8080);
    tcp->doff = 5;

    const char *http_payload =
        "GET /api/v1/metrics HTTP/1.1\r\n"
        "Host: monitor.internal\r\n"
        "User-Agent: CoreMonitorAgent/1.0\r\n"
        "Accept: text/plain\r\n\r\n";
    size_t payload_len = strlen(http_payload);

    uint8_t *payload_ptr = buffer + sizeof(struct ether_header) + 20 + 20;
    memcpy(payload_ptr, http_payload, payload_len);

    size_t total_len = sizeof(struct ether_header) + 20 + 20 + payload_len;

    cmonitor_packet_meta_t meta;
    int res = cmonitor_parse_packet(buffer, total_len, total_len, 4000, 0, &meta);
    assert(res == 0);
    assert(strcmp(meta.protocol, "TCP") == 0);
    assert(meta.dst_port == 8080);
    assert(strcmp(meta.service, "HTTP") == 0);
    assert(strcmp(meta.http_method, "GET") == 0);
    assert(strcmp(meta.http_uri, "/api/v1/metrics") == 0);
    assert(strcmp(meta.http_host, "monitor.internal") == 0);
    assert(strcmp(meta.http_user_agent, "CoreMonitorAgent/1.0") == 0);
    printf("✓ test_parse_http_request passed (Method: %s, Host: %s, URI: %s, UA: %s)\n",
           meta.http_method, meta.http_host, meta.http_uri, meta.http_user_agent);
}

static void test_parse_arp_reply() {
    uint8_t buffer[64] = {0};
    struct ether_header *eth = (struct ether_header*)buffer;
    eth->ether_type = htons(ETHERTYPE_ARP);

    uint8_t *arp_ptr = buffer + sizeof(struct ether_header);
    // hrd: 1 (Ethernet)
    arp_ptr[0] = 0x00; arp_ptr[1] = 0x01;
    // pro: 0x0800 (IPv4)
    arp_ptr[2] = 0x08; arp_ptr[3] = 0x00;
    // hln: 6, pln: 4
    arp_ptr[4] = 0x06; arp_ptr[5] = 0x04;
    // op: 2 (Reply)
    arp_ptr[6] = 0x00; arp_ptr[7] = 0x02;

    // Sender MAC: 00:0c:29:12:34:56
    uint8_t sender_mac[6] = {0x00, 0x0c, 0x29, 0x12, 0x34, 0x56};
    memcpy(arp_ptr + 8, sender_mac, 6);

    // Sender IP: 192.168.1.1
    inet_pton(AF_INET, "192.168.1.1", arp_ptr + 14);

    // Target MAC: 00:0c:29:aa:bb:cc
    uint8_t target_mac[6] = {0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc};
    memcpy(arp_ptr + 18, target_mac, 6);

    // Target IP: 192.168.1.100
    inet_pton(AF_INET, "192.168.1.100", arp_ptr + 24);

    size_t total_len = sizeof(struct ether_header) + 28;

    cmonitor_packet_meta_t meta;
    int res = cmonitor_parse_packet(buffer, total_len, total_len, 5000, 0, &meta);
    assert(res == 0);
    assert(strcmp(meta.protocol, "ARP") == 0);
    assert(strcmp(meta.service, "ARP-Reply") == 0);
    assert(meta.arp_opcode == 2);
    assert(strcmp(meta.src_ip, "192.168.1.1") == 0);
    assert(strcmp(meta.dst_ip, "192.168.1.100") == 0);
    assert(strcmp(meta.src_mac, "00:0c:29:12:34:56") == 0);
    printf("✓ test_parse_arp_reply passed (Src: %s [%s] -> Dst: %s)\n",
           meta.src_ip, meta.src_mac, meta.dst_ip);
}

void test_parse_8021q_vlan() {
    uint8_t buffer[128] = {0};
    struct ether_header *eth = (struct ether_header*)buffer;
    eth->ether_type = htons(0x8100); // 802.1Q VLAN Tag
    memset(eth->ether_shost, 0x11, 6);
    memset(eth->ether_dhost, 0x22, 6);

    // VLAN Tag (4 bytes): TCI (2 bytes: PRI=0, CFI=0, VID=100) + inner EtherType (0x0800 for IPv4)
    uint8_t *vlan = buffer + sizeof(struct ether_header);
    vlan[0] = 0x00;
    vlan[1] = 100; // VLAN ID: 100
    vlan[2] = 0x08;
    vlan[3] = 0x00; // Inner EtherType: IPv4

    size_t l3_offset = sizeof(struct ether_header) + 4;
    struct iphdr *ip = (struct iphdr*)(buffer + l3_offset);
    ip->ihl = 5;
    ip->version = 4;
    ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, "192.168.100.5", &ip->saddr);
    inet_pton(AF_INET, "10.10.10.1", &ip->daddr);

    struct tcphdr *tcp = (struct tcphdr*)(buffer + l3_offset + 20);
    tcp->source = htons(49152);
    tcp->dest = htons(443);
    tcp->doff = 5;

    cmonitor_packet_meta_t meta;
    int res = cmonitor_parse_packet(buffer, sizeof(buffer), sizeof(buffer), 2000, 0, &meta);
    assert(res == 0);
    assert(meta.vlan_id == 100);
    assert(strcmp(meta.protocol, "TCP") == 0);
    assert(strcmp(meta.src_ip, "192.168.100.5") == 0);
    assert(strcmp(meta.dst_ip, "10.10.10.1") == 0);
    assert(meta.dst_port == 443);
    printf("✓ test_parse_8021q_vlan passed (VLAN ID: %d, %s:%d -> %s:%d)\n",
           meta.vlan_id, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port);
}

void test_parse_ipv6_tcp() {
    uint8_t buffer[128] = {0};
    struct ether_header *eth = (struct ether_header*)buffer;
    eth->ether_type = htons(ETHERTYPE_IPV6);
    memset(eth->ether_shost, 0x33, 6);
    memset(eth->ether_dhost, 0x44, 6);

    size_t l3_offset = sizeof(struct ether_header);
    struct ip6_hdr *ip6 = (struct ip6_hdr*)(buffer + l3_offset);
    ip6->ip6_flow = htonl(0x60000000); // IPv6 version 6
    ip6->ip6_plen = htons(20);         // Payload length (20-byte TCP header)
    ip6->ip6_nxt = IPPROTO_TCP;        // Next header: TCP
    ip6->ip6_hlim = 64;
    inet_pton(AF_INET6, "2001:db8::1", &ip6->ip6_src);
    inet_pton(AF_INET6, "2607:f8b0:4005:805::200e", &ip6->ip6_dst);

    size_t l4_offset = l3_offset + sizeof(struct ip6_hdr);
    struct tcphdr *tcp = (struct tcphdr*)(buffer + l4_offset);
    tcp->source = htons(51234);
    tcp->dest = htons(443);
    tcp->doff = 5;
    buffer[l4_offset + 13] = 0x02; // SYN flag

    cmonitor_packet_meta_t meta;
    int res = cmonitor_parse_packet(buffer, sizeof(buffer), sizeof(buffer), 3000, 0, &meta);
    assert(res == 0);
    assert(strcmp(meta.protocol, "TCP") == 0);
    assert(strcmp(meta.src_ip, "2001:db8::1") == 0);
    assert(strcmp(meta.dst_ip, "2607:f8b0:4005:805::200e") == 0);
    assert(meta.src_port == 51234);
    assert(meta.dst_port == 443);
    assert(meta.tcp_flags & CMONITOR_TCP_SYN);
    assert(strcmp(meta.service, "HTTPS") == 0);
    printf("✓ test_parse_ipv6_tcp passed ([%s]:%d -> [%s]:%d, proto: %s, svc: %s)\n",
           meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port, meta.protocol, meta.service);
}

void test_parse_ipv4_malformed_ihl() {
    uint8_t buffer[64] = {0};
    struct ether_header *eth = (struct ether_header*)buffer;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
    ip->version = 4;
    ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, "10.0.0.1", &ip->saddr);
    inet_pton(AF_INET, "10.0.0.2", &ip->daddr);

    // Case 1: ihl < 5 (illegal IPv4 header length)
    ip->ihl = 4;
    cmonitor_packet_meta_t meta1;
    int res1 = cmonitor_parse_packet(buffer, sizeof(buffer), sizeof(buffer), 1000, 0, &meta1);
    assert(res1 == 0);
    // Protocol should not be parsed as TCP
    assert(strcmp(meta1.protocol, "OTHER") == 0);

    // Case 2: Truncated capture where caplen < ip_offset + ihl * 4
    ip->ihl = 10; // 40-byte IP header with options
    cmonitor_packet_meta_t meta2;
    // caplen is only 14 (eth) + 24 = 38 bytes < 14 + 40
    int res2 = cmonitor_parse_packet(buffer, 38, sizeof(buffer), 1000, 0, &meta2);
    assert(res2 == 0);
    assert(strcmp(meta2.protocol, "IPv4") == 0);
    assert(meta2.src_port == 0);
    assert(meta2.dst_port == 0);

    printf("✓ test_parse_ipv4_malformed_ihl passed\n");
}

void test_parse_tcp_malformed_doff() {
    uint8_t buffer[64] = {0};
    struct ether_header *eth = (struct ether_header*)buffer;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ether_header));
    ip->ihl = 5;
    ip->version = 4;
    ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, "10.0.0.1", &ip->saddr);
    inet_pton(AF_INET, "10.0.0.2", &ip->daddr);

    struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ether_header) + 20);
    tcp->source = htons(12345);
    tcp->dest = htons(80);
    // Malformed doff < 5
    tcp->doff = 2;

    cmonitor_packet_meta_t meta;
    int res = cmonitor_parse_packet(buffer, sizeof(buffer), sizeof(buffer), 1000, 0, &meta);
    assert(res == 0);
    assert(strcmp(meta.protocol, "TCP") == 0);
    assert(meta.src_port == 12345);
    assert(meta.dst_port == 80);
    assert(meta.payload_size == 0);
    assert(meta.service[0] != '\0'); // service assigned from port 80

    printf("✓ test_parse_tcp_malformed_doff passed\n");
}

int main() {
    printf("Running C Core Parser Tests...\n");
    test_parse_tcp_syn();
    test_parse_udp_dns();
    test_parse_tls_sni();
    test_parse_http_request();
    test_parse_arp_reply();
    test_parse_8021q_vlan();
    test_parse_ipv6_tcp();
    test_parse_ipv4_malformed_ihl();
    test_parse_tcp_malformed_doff();
    printf("All C Parser tests passed successfully!\n");
    return 0;
}
