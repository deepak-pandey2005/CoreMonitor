#include "cmonitor/ids.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_ids_blacklisted_ip() {
    cmonitor_ids_config_t cfg = cmonitor_ids_default_config();
    cmonitor_ids_t *ids = cmonitor_ids_init(&cfg);

    cmonitor_packet_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    meta.ts_sec = 1000;
    strncpy(meta.src_ip, "198.51.100.23", sizeof(meta.src_ip) - 1);
    strncpy(meta.dst_ip, "10.0.0.1", sizeof(meta.dst_ip) - 1);
    strncpy(meta.protocol, "TCP", sizeof(meta.protocol) - 1);
    meta.tcp_flags = CMONITOR_TCP_ACK;

    cmonitor_alert_t alerts[8];
    int count = cmonitor_ids_analyze(ids, &meta, alerts, 8);
    assert(count == 1);
    assert(strcmp(alerts[0].alert_type, "BLACKLISTED_IP") == 0);
    assert(alerts[0].severity == CMONITOR_SEV_CRITICAL);

    cmonitor_ids_free(ids);
    printf("✓ test_ids_blacklisted_ip passed\n");
}

void test_ids_suspicious_port() {
    cmonitor_ids_config_t cfg = cmonitor_ids_default_config();
    cmonitor_ids_t *ids = cmonitor_ids_init(&cfg);

    cmonitor_packet_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    meta.ts_sec = 1000;
    strncpy(meta.src_ip, "192.168.1.10", sizeof(meta.src_ip) - 1);
    strncpy(meta.dst_ip, "10.0.0.5", sizeof(meta.dst_ip) - 1);
    meta.dst_port = 4444; // Metasploit port
    strncpy(meta.protocol, "TCP", sizeof(meta.protocol) - 1);
    meta.tcp_flags = CMONITOR_TCP_SYN;

    cmonitor_alert_t alerts[8];
    int count = cmonitor_ids_analyze(ids, &meta, alerts, 8);
    assert(count == 1);
    assert(strcmp(alerts[0].alert_type, "SUSPICIOUS_PORT") == 0);
    assert(alerts[0].severity == CMONITOR_SEV_HIGH);

    cmonitor_ids_free(ids);
    printf("✓ test_ids_suspicious_port passed\n");
}

void test_ids_stealth_scans() {
    cmonitor_ids_config_t cfg = cmonitor_ids_default_config();
    cmonitor_ids_t *ids = cmonitor_ids_init(&cfg);

    cmonitor_alert_t alerts[8];

    // Xmas scan
    cmonitor_packet_meta_t xmas;
    memset(&xmas, 0, sizeof(xmas));
    xmas.ts_sec = 1000;
    strncpy(xmas.src_ip, "192.168.1.55", sizeof(xmas.src_ip) - 1);
    strncpy(xmas.protocol, "TCP", sizeof(xmas.protocol) - 1);
    xmas.tcp_flags = CMONITOR_TCP_FIN | CMONITOR_TCP_PSH | CMONITOR_TCP_URG;
    int c1 = cmonitor_ids_analyze(ids, &xmas, alerts, 8);
    assert(c1 == 1);
    assert(strcmp(alerts[0].alert_type, "XMAS_SCAN") == 0);

    // Null scan
    cmonitor_packet_meta_t null_pkt;
    memset(&null_pkt, 0, sizeof(null_pkt));
    null_pkt.ts_sec = 1000;
    strncpy(null_pkt.src_ip, "192.168.1.66", sizeof(null_pkt.src_ip) - 1);
    strncpy(null_pkt.protocol, "TCP", sizeof(null_pkt.protocol) - 1);
    null_pkt.tcp_flags = 0; // zero flags
    int c2 = cmonitor_ids_analyze(ids, &null_pkt, alerts, 8);
    assert(c2 == 1);
    assert(strcmp(alerts[0].alert_type, "NULL_SCAN") == 0);

    cmonitor_ids_free(ids);
    printf("✓ test_ids_stealth_scans passed\n");
}

void test_ids_port_scan_threshold() {
    cmonitor_ids_config_t cfg = cmonitor_ids_default_config();
    cfg.port_scan_threshold = 5; // set to 5 for test
    cfg.port_scan_window_sec = 10;
    cmonitor_ids_t *ids = cmonitor_ids_init(&cfg);

    int triggered = 0;
    for (uint16_t p = 100; p < 110; ++p) {
        cmonitor_packet_meta_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.ts_sec = 1000;
        strncpy(pkt.src_ip, "192.168.1.99", sizeof(pkt.src_ip) - 1);
        strncpy(pkt.dst_ip, "192.168.1.1", sizeof(pkt.dst_ip) - 1);
        pkt.dst_port = p;
        strncpy(pkt.protocol, "TCP", sizeof(pkt.protocol) - 1);
        pkt.tcp_flags = CMONITOR_TCP_SYN;

        cmonitor_alert_t alerts[8];
        int count = cmonitor_ids_analyze(ids, &pkt, alerts, 8);
        for (int i = 0; i < count; ++i) {
            if (strcmp(alerts[i].alert_type, "PORT_SCAN_SYN") == 0) {
                triggered = 1;
                break;
            }
        }
        if (triggered) break;
    }
    assert(triggered == 1);

    cmonitor_ids_free(ids);
    printf("✓ test_ids_port_scan_threshold passed\n");
}

void test_ids_dns_tunneling() {
    cmonitor_ids_config_t cfg = cmonitor_ids_default_config();
    cfg.dns_tunnel_len = 40;
    cmonitor_ids_t *ids = cmonitor_ids_init(&cfg);

    cmonitor_packet_meta_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.ts_sec = 1000;
    strncpy(pkt.src_ip, "192.168.1.25", sizeof(pkt.src_ip) - 1);
    strncpy(pkt.protocol, "UDP", sizeof(pkt.protocol) - 1);
    strncpy(pkt.dns_query, "v1-0a4fbc89e31d994e77a2810cd04481bc90aef.exfil-data.tunnel.attacker.xyz", sizeof(pkt.dns_query) - 1);

    cmonitor_alert_t alerts[8];
    int count = cmonitor_ids_analyze(ids, &pkt, alerts, 8);
    assert(count == 1);
    assert(strcmp(alerts[0].alert_type, "DNS_TUNNEL_ANOMALY") == 0);

    cmonitor_ids_free(ids);
    printf("✓ test_ids_dns_tunneling passed\n");
}

void test_ids_arp_spoofing() {
    cmonitor_ids_config_t cfg = cmonitor_ids_default_config();
    cmonitor_ids_t *ids = cmonitor_ids_init(&cfg);

    // 1. Legitimate Gateway ARP registration
    cmonitor_packet_meta_t pkt1;
    memset(&pkt1, 0, sizeof(pkt1));
    pkt1.ts_sec = 2000;
    snprintf(pkt1.protocol, sizeof(pkt1.protocol), "ARP");
    snprintf(pkt1.src_ip, sizeof(pkt1.src_ip), "192.168.1.1");
    snprintf(pkt1.src_mac, sizeof(pkt1.src_mac), "00:11:22:33:44:55");
    snprintf(pkt1.dst_ip, sizeof(pkt1.dst_ip), "192.168.1.100");
    pkt1.arp_opcode = 2; // Reply

    cmonitor_alert_t alerts[8];
    int count = cmonitor_ids_analyze(ids, &pkt1, alerts, 8);
    assert(count == 0);

    // 2. Attacker claims 192.168.1.1 with a different MAC (ARP Poisoning / Spoofing)
    cmonitor_packet_meta_t pkt2;
    memset(&pkt2, 0, sizeof(pkt2));
    pkt2.ts_sec = 2001;
    snprintf(pkt2.protocol, sizeof(pkt2.protocol), "ARP");
    snprintf(pkt2.src_ip, sizeof(pkt2.src_ip), "192.168.1.1");
    snprintf(pkt2.src_mac, sizeof(pkt2.src_mac), "aa:bb:cc:dd:ee:ff"); // Rogue MAC
    pkt2.arp_opcode = 2;

    count = cmonitor_ids_analyze(ids, &pkt2, alerts, 8);
    assert(count == 1);
    assert(strcmp(alerts[0].alert_type, "ARP_SPOOFING") == 0);
    assert(alerts[0].severity == CMONITOR_SEV_CRITICAL);

    // 3. Gratuitous ARP reply broadcast (src_ip == dst_ip)
    cmonitor_packet_meta_t pkt3;
    memset(&pkt3, 0, sizeof(pkt3));
    pkt3.ts_sec = 2002;
    snprintf(pkt3.protocol, sizeof(pkt3.protocol), "ARP");
    snprintf(pkt3.src_ip, sizeof(pkt3.src_ip), "192.168.1.200");
    snprintf(pkt3.src_mac, sizeof(pkt3.src_mac), "de:ad:be:ef:00:01");
    snprintf(pkt3.dst_ip, sizeof(pkt3.dst_ip), "192.168.1.200");
    pkt3.arp_opcode = 2;

    count = cmonitor_ids_analyze(ids, &pkt3, alerts, 8);
    assert(count == 1);
    assert(strcmp(alerts[0].alert_type, "GRATUITOUS_ARP") == 0);
    assert(alerts[0].severity == CMONITOR_SEV_HIGH);

    cmonitor_ids_free(ids);
    printf("✓ test_ids_arp_spoofing passed\n");
}

void test_ids_cooldown_and_host_saturation() {
    cmonitor_ids_config_t cfg = cmonitor_ids_default_config();
    cmonitor_ids_t *ids = cmonitor_ids_init(&cfg);

    cmonitor_alert_t alerts[8];

    // 1. Fill cooldown slots with 300 unique host/port pairs at ts_sec = 1000
    for (int i = 0; i < 300; ++i) {
        cmonitor_packet_meta_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.ts_sec = 1000;
        snprintf(pkt.src_ip, sizeof(pkt.src_ip), "10.0.%d.%d", (i >> 8) & 0xff, i & 0xff);
        snprintf(pkt.dst_ip, sizeof(pkt.dst_ip), "192.168.1.1");
        pkt.dst_port = 4444; // Metasploit port -> SUSPICIOUS_PORT
        snprintf(pkt.protocol, sizeof(pkt.protocol), "TCP");
        pkt.tcp_flags = CMONITOR_TCP_SYN;

        // The first alert for each target should register
        int count = cmonitor_ids_analyze(ids, &pkt, alerts, 8);
        assert(count == 1);
    }

    // 2. Immediate duplicate query should be suppressed (< 10 sec)
    cmonitor_packet_meta_t pkt_dup;
    memset(&pkt_dup, 0, sizeof(pkt_dup));
    pkt_dup.ts_sec = 1005;
    snprintf(pkt_dup.src_ip, sizeof(pkt_dup.src_ip), "10.0.0.0");
    snprintf(pkt_dup.dst_ip, sizeof(pkt_dup.dst_ip), "192.168.1.1");
    pkt_dup.dst_port = 4444;
    snprintf(pkt_dup.protocol, sizeof(pkt_dup.protocol), "TCP");
    pkt_dup.tcp_flags = CMONITOR_TCP_SYN;

    int dup_count = cmonitor_ids_analyze(ids, &pkt_dup, alerts, 8);
    assert(dup_count == 0); // suppressed

    // 3. At ts_sec = 1015 (> 10s cooldown), expired slots are recycled and new alerts fire
    cmonitor_packet_meta_t pkt_expired;
    memset(&pkt_expired, 0, sizeof(pkt_expired));
    pkt_expired.ts_sec = 1015;
    snprintf(pkt_expired.src_ip, sizeof(pkt_expired.src_ip), "10.0.0.0");
    snprintf(pkt_expired.dst_ip, sizeof(pkt_expired.dst_ip), "192.168.1.1");
    pkt_expired.dst_port = 4444;
    snprintf(pkt_expired.protocol, sizeof(pkt_expired.protocol), "TCP");
    pkt_expired.tcp_flags = CMONITOR_TCP_SYN;

    int exp_count = cmonitor_ids_analyze(ids, &pkt_expired, alerts, 8);
    assert(exp_count == 1); // alert fires again!

    cmonitor_ids_free(ids);
    printf("✓ test_ids_cooldown_and_host_saturation passed\n");
}

void test_ids_icmpv6_flood() {
    cmonitor_ids_config_t cfg = cmonitor_ids_default_config();
    cfg.icmp_flood_threshold = 10;
    cfg.icmp_flood_window_sec = 2;
    cmonitor_ids_t *ids = cmonitor_ids_init(&cfg);

    cmonitor_alert_t alerts[8];
    int triggered = 0;

    for (int i = 0; i < 15; ++i) {
        cmonitor_packet_meta_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.ts_sec = 1000;
        snprintf(pkt.src_ip, sizeof(pkt.src_ip), "2001:db8::100");
        snprintf(pkt.dst_ip, sizeof(pkt.dst_ip), "2001:db8::1");
        snprintf(pkt.protocol, sizeof(pkt.protocol), "ICMPv6");

        int count = cmonitor_ids_analyze(ids, &pkt, alerts, 8);
        for (int j = 0; j < count; ++j) {
            if (strcmp(alerts[j].alert_type, "ICMP_FLOOD") == 0) {
                triggered = 1;
                assert(strstr(alerts[j].message, "ICMPv6") != NULL);
                break;
            }
        }
        if (triggered) break;
    }
    assert(triggered == 1);

    cmonitor_ids_free(ids);
    printf("✓ test_ids_icmpv6_flood passed\n");
}

int main() {
    printf("Running C Core IDS Engine Tests...\n");
    test_ids_blacklisted_ip();
    test_ids_suspicious_port();
    test_ids_stealth_scans();
    test_ids_port_scan_threshold();
    test_ids_dns_tunneling();
    test_ids_arp_spoofing();
    test_ids_cooldown_and_host_saturation();
    test_ids_icmpv6_flood();
    printf("All C IDS Engine tests passed successfully!\n");
    return 0;
}
