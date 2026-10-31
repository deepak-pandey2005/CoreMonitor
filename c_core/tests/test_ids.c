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

int main() {
    printf("Running C Core IDS Engine Tests...\n");
    test_ids_blacklisted_ip();
    test_ids_suspicious_port();
    test_ids_stealth_scans();
    test_ids_port_scan_threshold();
    test_ids_dns_tunneling();
    printf("All C IDS Engine tests passed successfully!\n");
    return 0;
}
