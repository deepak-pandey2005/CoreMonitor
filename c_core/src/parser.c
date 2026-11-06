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
#include <strings.h>

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

struct __attribute__((packed)) cmon_arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t  hln;
    uint8_t  pln;
    uint16_t op;
    uint8_t  sha[6];
    uint8_t  spa[4];
    uint8_t  tha[6];
    uint8_t  tpa[4];
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

static void parse_tls_sni(const uint8_t *data, size_t len, char *out_sni, size_t max_len) {
    out_sni[0] = '\0';
    if (len < 44) return;

    // Byte 0: 0x16 = TLS Handshake record
    if (data[0] != 0x16) return;

    // Byte 5: 0x01 = Client Hello message
    if (data[5] != 0x01) return;

    size_t offset = 43; // Points to Session ID Length
    if (offset >= len) return;
    uint8_t session_id_len = data[offset++];
    offset += session_id_len;

    // Cipher Suites Length
    if (offset + 2 > len) return;
    uint16_t cipher_suites_len = (data[offset] << 8) | data[offset + 1];
    offset += 2 + cipher_suites_len;

    // Compression Methods Length
    if (offset + 1 > len) return;
    uint8_t comp_len = data[offset++];
    offset += comp_len;

    // Extensions Length
    if (offset + 2 > len) return;
    uint16_t extensions_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    size_t ext_end = offset + extensions_len;
    if (ext_end > len) ext_end = len;

    while (offset + 4 <= ext_end) {
        uint16_t ext_type = (data[offset] << 8) | data[offset + 1];
        uint16_t ext_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + ext_len > ext_end) break;

        // Extension 0x0000 = server_name (SNI)
        if (ext_type == 0x0000 && ext_len >= 5) {
            uint8_t name_type = data[offset + 2];
            uint16_t name_len = (data[offset + 3] << 8) | data[offset + 4];
            if (name_type == 0x00 && offset + 5 + name_len <= ext_end) {
                size_t copy_len = name_len < (max_len - 1) ? name_len : (max_len - 1);
                memcpy(out_sni, data + offset + 5, copy_len);
                out_sni[copy_len] = '\0';
                return;
            }
        }
        offset += ext_len;
    }
}

static void parse_http_request(const uint8_t *data, size_t len,
                               char *out_method, size_t max_method,
                               char *out_uri, size_t max_uri,
                               char *out_host, size_t max_host,
                               char *out_user_agent, size_t max_ua) {
    out_method[0] = '\0';
    out_uri[0] = '\0';
    out_host[0] = '\0';
    out_user_agent[0] = '\0';

    if (len < 10) return;

    const char *methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "TRACE ", "CONNECT ", "PATCH "};
    const size_t method_lens[] = {4, 5, 5, 4, 7, 8, 6, 8, 6};
    int method_idx = -1;

    for (size_t m = 0; m < sizeof(methods) / sizeof(methods[0]); m++) {
        if (len >= method_lens[m] && memcmp(data, methods[m], method_lens[m]) == 0) {
            method_idx = (int)m;
            break;
        }
    }

    if (method_idx == -1) return;

    size_t m_len = method_lens[method_idx] - 1;
    size_t copy_m = m_len < (max_method - 1) ? m_len : (max_method - 1);
    memcpy(out_method, data, copy_m);
    out_method[copy_m] = '\0';

    size_t uri_start = method_lens[method_idx];
    size_t cur = uri_start;
    while (cur < len && data[cur] != ' ' && data[cur] != '\r' && data[cur] != '\n') {
        cur++;
    }
    size_t uri_len = cur - uri_start;
    if (uri_len > 0) {
        size_t copy_uri = uri_len < (max_uri - 1) ? uri_len : (max_uri - 1);
        memcpy(out_uri, data + uri_start, copy_uri);
        out_uri[copy_uri] = '\0';
    }

    while (cur < len && data[cur] != '\n') {
        cur++;
    }
    if (cur < len && data[cur] == '\n') cur++;

    while (cur < len) {
        if (data[cur] == '\r' && cur + 1 < len && data[cur + 1] == '\n') break;
        if (data[cur] == '\n') break;

        size_t line_start = cur;
        while (cur < len && data[cur] != '\n') {
            cur++;
        }
        size_t line_end = cur;
        if (line_end > line_start && data[line_end - 1] == '\r') {
            line_end--;
        }
        size_t line_len = line_end - line_start;

        if (line_len > 5 && strncasecmp((const char*)(data + line_start), "Host:", 5) == 0) {
            size_t val_start = line_start + 5;
            while (val_start < line_end && (data[val_start] == ' ' || data[val_start] == '\t')) val_start++;
            size_t val_len = line_end - val_start;
            if (val_len > 0) {
                size_t copy_h = val_len < (max_host - 1) ? val_len : (max_host - 1);
                memcpy(out_host, data + val_start, copy_h);
                out_host[copy_h] = '\0';
            }
        } else if (line_len > 11 && strncasecmp((const char*)(data + line_start), "User-Agent:", 11) == 0) {
            size_t val_start = line_start + 11;
            while (val_start < line_end && (data[val_start] == ' ' || data[val_start] == '\t')) val_start++;
            size_t val_len = line_end - val_start;
            if (val_len > 0) {
                size_t copy_ua = val_len < (max_ua - 1) ? val_len : (max_ua - 1);
                memcpy(out_user_agent, data + val_start, copy_ua);
                out_user_agent[copy_ua] = '\0';
            }
        }

        if (cur < len && data[cur] == '\n') cur++;
    }
}

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

static void parse_l4_protocol(const uint8_t *data, uint32_t caplen, size_t l4_offset,
                              uint8_t protocol, cmonitor_packet_meta_t *out) {
    if (l4_offset >= caplen) return;

    if (protocol == IPPROTO_TCP) {
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

            if (tcp->doff < 5) return;
            size_t tcp_hdr_len = (size_t)tcp->doff * 4;
            if (caplen < l4_offset + tcp_hdr_len) return;
            size_t payload_offset = l4_offset + tcp_hdr_len;
            if (caplen > payload_offset) {
                out->payload_size = caplen - payload_offset;

                // Extract TLS SNI from Client Hello
                if (out->dst_port == 443 || out->src_port == 443 || data[payload_offset] == 0x16) {
                    parse_tls_sni(data + payload_offset, out->payload_size,
                                  out->tls_sni, sizeof(out->tls_sni));
                    if (out->tls_sni[0] != '\0' && out->service[0] == '\0') {
                        strncpy(out->service, "HTTPS", sizeof(out->service) - 1);
                    }
                }

                // Extract HTTP Request Metadata (GET, POST, etc.)
                parse_http_request(data + payload_offset, out->payload_size,
                                   out->http_method, sizeof(out->http_method),
                                   out->http_uri, sizeof(out->http_uri),
                                   out->http_host, sizeof(out->http_host),
                                   out->http_user_agent, sizeof(out->http_user_agent));
                if (out->http_method[0] != '\0' && out->service[0] == '\0') {
                    strncpy(out->service, "HTTP", sizeof(out->service) - 1);
                }
            }
        }
    } else if (protocol == IPPROTO_UDP) {
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
    } else if (protocol == IPPROTO_ICMP) {
        strncpy(out->protocol, "ICMP", sizeof(out->protocol) - 1);
        if (caplen >= l4_offset + sizeof(struct icmphdr)) {
            size_t payload_offset = l4_offset + sizeof(struct icmphdr);
            if (caplen > payload_offset) {
                out->payload_size = caplen - payload_offset;
            }
        }
    } else if (protocol == IPPROTO_ICMPV6) {
        strncpy(out->protocol, "ICMPv6", sizeof(out->protocol) - 1);
        size_t payload_offset = l4_offset + 8; // ICMPv6 header is 8 bytes
        if (caplen > payload_offset) {
            out->payload_size = caplen - payload_offset;
        }
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

    /* Unpack 802.1Q / 802.1ad VLAN tags (including stacked QinQ) */
    while (ether_type == 0x8100 || ether_type == 0x88a8 || ether_type == 0x9100) {
        if (caplen < ip_offset + 4) return 0;
        uint16_t tci = (data[ip_offset] << 8) | data[ip_offset + 1];
        out->vlan_id = tci & 0x0FFF;
        ether_type = (data[ip_offset + 2] << 8) | data[ip_offset + 3];
        ip_offset += 4;
    }

    if (ether_type == ETHERTYPE_IP) {
        if (caplen < ip_offset + sizeof(struct iphdr)) return 0;
        const struct iphdr *ip = (const struct iphdr*)(data + ip_offset);
        if (ip->ihl < 5) return 0;

        inet_ntop(AF_INET, &(ip->saddr), out->src_ip, sizeof(out->src_ip));
        inet_ntop(AF_INET, &(ip->daddr), out->dst_ip, sizeof(out->dst_ip));
        strncpy(out->protocol, "IPv4", sizeof(out->protocol) - 1);

        size_t dst_len = strlen(out->dst_ip);
        if (strcmp(out->dst_ip, "255.255.255.255") == 0 ||
            (dst_len >= 4 && strcmp(out->dst_ip + dst_len - 4, ".255") == 0)) {
            out->is_broadcast = 1;
        }

        size_t ip_hdr_len = (size_t)ip->ihl * 4;
        if (caplen < ip_offset + ip_hdr_len) return 0;
        size_t l4_offset = ip_offset + ip_hdr_len;
        parse_l4_protocol(data, caplen, l4_offset, ip->protocol, out);
    } else if (ether_type == ETHERTYPE_IPV6) {
        if (caplen < ip_offset + sizeof(struct ip6_hdr)) return 0;
        const struct ip6_hdr *ip6 = (const struct ip6_hdr*)(data + ip_offset);

        inet_ntop(AF_INET6, &(ip6->ip6_src), out->src_ip, sizeof(out->src_ip));
        inet_ntop(AF_INET6, &(ip6->ip6_dst), out->dst_ip, sizeof(out->dst_ip));
        strncpy(out->protocol, "IPv6", sizeof(out->protocol) - 1);

        if (strncmp(out->dst_ip, "ff02:", 5) == 0) {
            out->is_broadcast = 1;
        }

        uint8_t next_hdr = ip6->ip6_nxt;
        size_t l4_offset = ip_offset + sizeof(struct ip6_hdr);

        while (l4_offset < caplen &&
               (next_hdr == IPPROTO_HOPOPTS || next_hdr == IPPROTO_ROUTING ||
                next_hdr == IPPROTO_FRAGMENT || next_hdr == IPPROTO_DSTOPTS)) {
            if (l4_offset + 2 > caplen) break;
            uint8_t hdr_ext_len = data[l4_offset + 1];
            size_t ext_len = (next_hdr == IPPROTO_FRAGMENT) ? 8 : (size_t)(hdr_ext_len + 1) * 8;
            next_hdr = data[l4_offset];
            l4_offset += ext_len;
        }

        parse_l4_protocol(data, caplen, l4_offset, next_hdr, out);
    } else if (ether_type == ETHERTYPE_ARP) {
        strncpy(out->protocol, "ARP", sizeof(out->protocol) - 1);
        out->is_broadcast = 1;
        if (caplen >= ip_offset + sizeof(struct cmon_arp_hdr)) {
            const struct cmon_arp_hdr *arp = (const struct cmon_arp_hdr*)(data + ip_offset);
            out->arp_opcode = ntohs(arp->op);
            inet_ntop(AF_INET, arp->spa, out->src_ip, sizeof(out->src_ip));
            inet_ntop(AF_INET, arp->tpa, out->dst_ip, sizeof(out->dst_ip));
            format_mac(arp->sha, out->src_mac, sizeof(out->src_mac));
            format_mac(arp->tha, out->dst_mac, sizeof(out->dst_mac));
            if (out->arp_opcode == 1) {
                strncpy(out->service, "ARP-Req", sizeof(out->service) - 1);
            } else if (out->arp_opcode == 2) {
                strncpy(out->service, "ARP-Reply", sizeof(out->service) - 1);
            } else {
                strncpy(out->service, "ARP", sizeof(out->service) - 1);
            }
        }
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
