#include "cmonitor/parser.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint16_t port;
    const char *service;
} service_map_t;

static const service_map_t WELL_KNOWN_SERVICES[] = {
    {20, "FTP-Data"},
    {21, "FTP"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {53, "DNS"},
    {67, "DHCP-Server"},
    {68, "DHCP-Client"},
    {80, "HTTP"},
    {110, "POP3"},
    {123, "NTP"},
    {143, "IMAP"},
    {443, "HTTPS"},
    {445, "SMB"},
    {1337, "Backdoor-1337"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {4444, "Metasploit"},
    {5432, "PostgreSQL"},
    {6379, "Redis"},
    {8080, "HTTP-Proxy"},
    {31337, "Back-Orifice"},
    {0, NULL}
};

const char* cmonitor_get_service_name(uint16_t port) {
    for (size_t i = 0; WELL_KNOWN_SERVICES[i].service != NULL; ++i) {
        if (WELL_KNOWN_SERVICES[i].port == port) {
            return WELL_KNOWN_SERVICES[i].service;
        }
    }
    return "";
}

static void format_mac(const uint8_t *mac, char *out, size_t max_len) {
    snprintf(out, max_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void parse_dns_query(const uint8_t *payload, size_t len, char *out_domain, size_t max_domain_len, uint16_t *out_qtype) {
    out_domain[0] = '\0';
    *out_qtype = 1;
    if (len < 12) return;

    size_t offset = 12;
    size_t out_idx = 0;

    while (offset < len) {
        uint8_t label_len = payload[offset++];
        if (label_len == 0) break;
        if ((label_len & 0xC0) == 0xC0) {
            offset++;
            break;
        }
        if (offset + label_len > len) break;

        if (out_idx > 0 && out_idx + 1 < max_domain_len) {
            out_domain[out_idx++] = '.';
        }

        for (uint8_t i = 0; i < label_len && out_idx + 1 < max_domain_len; ++i) {
            out_domain[out_idx++] = (char)payload[offset + i];
        }
        offset += label_len;
    }
    out_domain[out_idx] = '\0';

    if (offset + 4 <= len) {
        *out_qtype = (payload[offset] << 8) | payload[offset + 1];
    }
}

int cmonitor_parse_packet(const uint8_t *data, uint32_t caplen, uint32_t len,
                          int64_t sec, int64_t usec, cmonitor_packet_meta_t *out) {
    if (!data || !out) return -1;
    memset(out, 0, sizeof(*out));

    out->ts_sec = sec;
    out->ts_usec = usec;
    out->packet_size = len;
    strncpy(out->src_ip, "unknown", sizeof(out->src_ip) - 1);
    strncpy(out->dst_ip, "unknown", sizeof(out->dst_ip) - 1);
    strncpy(out->protocol, "OTHER", sizeof(out->protocol) - 1);

    if (caplen < sizeof(struct ether_header)) {
        return 0;
    }

    const struct ether_header *eth = (const struct ether_header*)data;
    format_mac(eth->ether_shost, out->src_mac, sizeof(out->src_mac));
    format_mac(eth->ether_dhost, out->dst_mac, sizeof(out->dst_mac));

    if (strcmp(out->dst_mac, "ff:ff:ff:ff:ff:ff") == 0) {
        out->is_broadcast = 1;
    }

    uint16_t ether_type = ntohs(eth->ether_type);
    size_t ip_offset = sizeof(struct ether_header);

    if (ether_type == ETHERTYPE_IP) {
        if (caplen < ip_offset + sizeof(struct iphdr)) return 0;
        const struct iphdr *ip = (const struct iphdr*)(data + ip_offset);

        inet_ntop(AF_INET, &(ip->saddr), out->src_ip, sizeof(out->src_ip));
        inet_ntop(AF_INET, &(ip->daddr), out->dst_ip, sizeof(out->dst_ip));
        strncpy(out->protocol, "IPv4", sizeof(out->protocol) - 1);

        size_t dst_len = strlen(out->dst_ip);
        if (strcmp(out->dst_ip, "255.255.255.255") == 0 ||
            (dst_len >= 4 && strcmp(out->dst_ip + dst_len - 4, ".255") == 0)) {
            out->is_broadcast = 1;
        }

        size_t ip_hdr_len = ip->ihl * 4;
        size_t l4_offset = ip_offset + ip_hdr_len;

        if (ip->protocol == IPPROTO_TCP) {
            strncpy(out->protocol, "TCP", sizeof(out->protocol) - 1);
            if (caplen >= l4_offset + sizeof(struct tcphdr)) {
                const struct tcphdr *tcp = (const struct tcphdr*)(data + l4_offset);
                out->src_port = ntohs(tcp->source);
                out->dst_port = ntohs(tcp->dest);

                uint8_t flags = data[l4_offset + 13];
                char flag_str[32] = {0};
                int flag_len = 0;

                if (flags & 0x01) { out->tcp_flags |= CMONITOR_TCP_FIN; flag_len += snprintf(flag_str + flag_len, sizeof(flag_str) - flag_len, "FIN,"); }
                if (flags & 0x02) { out->tcp_flags |= CMONITOR_TCP_SYN; flag_len += snprintf(flag_str + flag_len, sizeof(flag_str) - flag_len, "SYN,"); }
                if (flags & 0x04) { out->tcp_flags |= CMONITOR_TCP_RST; flag_len += snprintf(flag_str + flag_len, sizeof(flag_str) - flag_len, "RST,"); }
                if (flags & 0x08) { out->tcp_flags |= CMONITOR_TCP_PSH; flag_len += snprintf(flag_str + flag_len, sizeof(flag_str) - flag_len, "PSH,"); }
                if (flags & 0x10) { out->tcp_flags |= CMONITOR_TCP_ACK; flag_len += snprintf(flag_str + flag_len, sizeof(flag_str) - flag_len, "ACK,"); }
                if (flags & 0x20) { out->tcp_flags |= CMONITOR_TCP_URG; flag_len += snprintf(flag_str + flag_len, sizeof(flag_str) - flag_len, "URG,"); }

                if (flag_len > 0 && flag_str[flag_len - 1] == ',') {
                    flag_str[flag_len - 1] = '\0';
                }
                snprintf(out->tcp_flags_str, sizeof(out->tcp_flags_str), "%s", flag_str);

                size_t tcp_hdr_len = tcp->doff * 4;
                size_t payload_offset = l4_offset + tcp_hdr_len;
                if (caplen > payload_offset) {
                    out->payload_size = caplen - payload_offset;
                }
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            strncpy(out->protocol, "UDP", sizeof(out->protocol) - 1);
            if (caplen >= l4_offset + sizeof(struct udphdr)) {
                const struct udphdr *udp = (const struct udphdr*)(data + l4_offset);
                out->src_port = ntohs(udp->source);
                out->dst_port = ntohs(udp->dest);

                size_t payload_offset = l4_offset + sizeof(struct udphdr);
                if (caplen > payload_offset) {
                    out->payload_size = caplen - payload_offset;
                    if (out->src_port == 53 || out->dst_port == 53) {
                        strncpy(out->service, "DNS", sizeof(out->service) - 1);
                        parse_dns_query(data + payload_offset, out->payload_size,
                                        out->dns_query, sizeof(out->dns_query), &out->dns_type);
                    }
                }
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            strncpy(out->protocol, "ICMP", sizeof(out->protocol) - 1);
            if (caplen >= l4_offset + sizeof(struct icmphdr)) {
                size_t payload_offset = l4_offset + sizeof(struct icmphdr);
                if (caplen > payload_offset) {
                    out->payload_size = caplen - payload_offset;
                }
            }
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        if (caplen < ip_offset + sizeof(struct ip6_hdr)) return 0;
        const struct ip6_hdr *ip6 = (const struct ip6_hdr*)(data + ip_offset);

        inet_ntop(AF_INET6, &(ip6->ip6_src), out->src_ip, sizeof(out->src_ip));
        inet_ntop(AF_INET6, &(ip6->ip6_dst), out->dst_ip, sizeof(out->dst_ip));
        strncpy(out->protocol, "IPv6", sizeof(out->protocol) - 1);

        if (strncmp(out->dst_ip, "ff02:", 5) == 0) {
            out->is_broadcast = 1;
        }
    } else if (ether_type == ETHERTYPE_ARP) {
        strncpy(out->protocol, "ARP", sizeof(out->protocol) - 1);
        out->is_broadcast = 1;
    }

    if (out->service[0] == '\0') {
        const char *svc = "";
        if (out->dst_port > 0) svc = cmonitor_get_service_name(out->dst_port);
        if (svc[0] == '\0' && out->src_port > 0) svc = cmonitor_get_service_name(out->src_port);
        if (svc[0] != '\0') {
            strncpy(out->service, svc, sizeof(out->service) - 1);
        }
    }

    return 0;
}
