#ifndef CMONITOR_PACKET_H
#define CMONITOR_PACKET_H

#include <stdint.h>
#include <stdbool.h>

#define CMONITOR_TCP_FIN 0x01
#define CMONITOR_TCP_SYN 0x02
#define CMONITOR_TCP_RST 0x04
#define CMONITOR_TCP_PSH 0x08
#define CMONITOR_TCP_ACK 0x10
#define CMONITOR_TCP_URG 0x20

typedef struct {
    int64_t ts_sec;
    int64_t ts_usec;
    char src_ip[64];
    char dst_ip[64];
    char src_mac[18];
    char dst_mac[18];
    uint16_t src_port;
    uint16_t dst_port;
    char protocol[16];        /* "TCP", "UDP", "ICMP", "ARP", "IPv4", "IPv6", "OTHER" */
    char service[32];         /* "HTTP", "HTTPS", "DNS", "SSH", etc. */
    uint32_t packet_size;
    uint32_t payload_size;
    uint8_t tcp_flags;        /* Bitmask of CMONITOR_TCP_* */
    char tcp_flags_str[32];   /* Human-readable comma-delimited flags */
    char dns_query[256];
    uint16_t dns_type;
    char tls_sni[256];        /* Extracted TLS Server Name Indication (SNI) */
    uint8_t is_broadcast;
} cmonitor_packet_meta_t;

#endif /* CMONITOR_PACKET_H */
