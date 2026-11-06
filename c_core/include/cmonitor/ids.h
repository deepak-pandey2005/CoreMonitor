#ifndef CMONITOR_IDS_H
#define CMONITOR_IDS_H

#include "cmonitor/packet.h"
#include <stdint.h>
#include <stddef.h>

#define CMONITOR_SEV_LOW      0
#define CMONITOR_SEV_MEDIUM   1
#define CMONITOR_SEV_HIGH     2
#define CMONITOR_SEV_CRITICAL 3

typedef struct {
    int64_t ts_sec;
    int64_t ts_usec;
    int severity;
    char alert_type[32];
    char message[256];
    char src_ip[64];
    char dst_ip[64];
    uint16_t src_port;
    uint16_t dst_port;
    char protocol[16];
    char details[256];
} cmonitor_alert_t;

typedef struct {
    int enabled;
    int port_scan_threshold;
    int port_scan_window_sec;
    int syn_flood_threshold;
    int syn_flood_window_sec;
    size_t bw_spike_bytes_sec;
    int bw_window_sec;
    size_t dns_tunnel_len;
    int icmp_flood_threshold;
    int icmp_flood_window_sec;
    int udp_flood_threshold;
    int udp_flood_window_sec;
} cmonitor_ids_config_t;

typedef struct cmonitor_ids cmonitor_ids_t;

#ifdef __cplusplus
extern "C" {
#endif

cmonitor_ids_config_t cmonitor_ids_default_config(void);

cmonitor_ids_t* cmonitor_ids_init(const cmonitor_ids_config_t *config);

int cmonitor_ids_analyze(cmonitor_ids_t *ids, const cmonitor_packet_meta_t *meta,
                         cmonitor_alert_t *out_alerts, int max_alerts);

void cmonitor_ids_free(cmonitor_ids_t *ids);

const char* cmonitor_severity_str(int severity);

#ifdef __cplusplus
}
#endif

#endif /* CMONITOR_IDS_H */
