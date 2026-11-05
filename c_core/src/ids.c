#include "cmonitor/ids.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TRACKED_HOSTS 512
#define MAX_PORT_EVENTS   64
#define MAX_SYN_EVENTS    128
#define MAX_ICMP_EVENTS   64
#define MAX_BW_EVENTS     64
#define MAX_COOLDOWNS     256
#define MAX_ARP_ENTRIES   256

typedef struct {
    char ip[64];
    char mac[18];
    int64_t last_seen_sec;
    int in_use;
} arp_entry_t;

typedef struct {
    int64_t ts_sec;
    uint16_t port;
} port_event_t;

typedef struct {
    int64_t ts_sec;
    size_t bytes;
} bw_event_t;

typedef struct {
    char ip[64];
    int in_use;

    /* Port scan tracking */
    port_event_t port_events[MAX_PORT_EVENTS];
    int port_head;
    int port_count;

    /* SYN flood tracking */
    int64_t syn_events[MAX_SYN_EVENTS];
    int syn_head;
    int syn_count;

    /* ICMP flood tracking */
    int64_t icmp_events[MAX_ICMP_EVENTS];
    int icmp_head;
    int icmp_count;

    /* Bandwidth tracking */
    bw_event_t bw_events[MAX_BW_EVENTS];
    int bw_head;
    int bw_count;
} host_tracker_t;

typedef struct {
    char key[96]; /* alert_type + ":" + ip */
    int64_t last_alert_sec;
    int in_use;
} cooldown_entry_t;

struct cmonitor_ids {
    cmonitor_ids_config_t cfg;
    host_tracker_t hosts[MAX_TRACKED_HOSTS];
    cooldown_entry_t cooldowns[MAX_COOLDOWNS];
    arp_entry_t arp_table[MAX_ARP_ENTRIES];
};

static const char* BLACKLIST_IPS[] = {
    "198.51.100.23",
    "203.0.113.50",
    "185.220.101.5",
    NULL
};

typedef struct {
    uint16_t port;
    const char *desc;
    int severity;
} suspicious_port_entry_t;

static const suspicious_port_entry_t SUSPICIOUS_PORTS[] = {
    {21, "FTP (Insecure Cleartext Protocol)", CMONITOR_SEV_MEDIUM},
    {23, "Telnet (Insecure Cleartext Protocol)", CMONITOR_SEV_MEDIUM},
    {4444, "Metasploit Default C2 Listener", CMONITOR_SEV_HIGH},
    {1337, "Common Hacker / Backdoor Port", CMONITOR_SEV_HIGH},
    {31337, "Back Orifice Trojan Port", CMONITOR_SEV_HIGH},
    {5555, "Android ADB Exposed / Trojan Port", CMONITOR_SEV_HIGH},
    {6667, "IRC (Historical Botnet C2)", CMONITOR_SEV_MEDIUM},
    {0, NULL, 0}
};

const char* cmonitor_severity_str(int severity) {
    switch (severity) {
        case CMONITOR_SEV_LOW: return "LOW";
        case CMONITOR_SEV_MEDIUM: return "MEDIUM";
        case CMONITOR_SEV_HIGH: return "HIGH";
        case CMONITOR_SEV_CRITICAL: return "CRITICAL";
        default: return "INFO";
    }
}

cmonitor_ids_config_t cmonitor_ids_default_config(void) {
    cmonitor_ids_config_t cfg;
    cfg.enabled = 1;
    cfg.port_scan_threshold = 15;
    cfg.port_scan_window_sec = 10;
    cfg.syn_flood_threshold = 100;
    cfg.syn_flood_window_sec = 2;
    cfg.bw_spike_bytes_sec = 10000000; /* 10 MB/s */
    cfg.bw_window_sec = 2;
    cfg.dns_tunnel_len = 60;
    cfg.icmp_flood_threshold = 50;
    cfg.icmp_flood_window_sec = 2;
    return cfg;
}

cmonitor_ids_t* cmonitor_ids_init(const cmonitor_ids_config_t *config) {
    cmonitor_ids_t *ids = (cmonitor_ids_t*)calloc(1, sizeof(cmonitor_ids_t));
    if (!ids) return NULL;
    if (config) {
        ids->cfg = *config;
    } else {
        ids->cfg = cmonitor_ids_default_config();
    }
    return ids;
}

void cmonitor_ids_free(cmonitor_ids_t *ids) {
    if (ids) free(ids);
}

static unsigned int hash_str(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

static host_tracker_t* get_host_tracker(cmonitor_ids_t *ids, const char *ip) {
    if (!ip || ip[0] == '\0' || strcmp(ip, "unknown") == 0) return NULL;
    unsigned int h = hash_str(ip) % MAX_TRACKED_HOSTS;
    for (int i = 0; i < MAX_TRACKED_HOSTS; ++i) {
        int idx = (h + i) % MAX_TRACKED_HOSTS;
        if (!ids->hosts[idx].in_use) {
            ids->hosts[idx].in_use = 1;
            snprintf(ids->hosts[idx].ip, sizeof(ids->hosts[idx].ip), "%s", ip);
            return &ids->hosts[idx];
        }
        if (strcmp(ids->hosts[idx].ip, ip) == 0) {
            return &ids->hosts[idx];
        }
    }
    /* Fallback slot eviction when host table is completely saturated:
     * re-initialize state to prevent attack history bleeding from displaced host. */
    memset(&ids->hosts[h], 0, sizeof(host_tracker_t));
    ids->hosts[h].in_use = 1;
    snprintf(ids->hosts[h].ip, sizeof(ids->hosts[h].ip), "%s", ip);
    return &ids->hosts[h];
}

static int should_suppress(cmonitor_ids_t *ids, const char *alert_type, const char *key, int64_t now_sec) {
    char full_key[96];
    snprintf(full_key, sizeof(full_key), "%s:%s", alert_type, key);
    unsigned int h = hash_str(full_key) % MAX_COOLDOWNS;
    int first_expired_idx = -1;
    int oldest_idx = h;
    int64_t oldest_ts = ids->cooldowns[h].last_alert_sec;

    for (int i = 0; i < MAX_COOLDOWNS; ++i) {
        int idx = (h + i) % MAX_COOLDOWNS;
        if (!ids->cooldowns[idx].in_use) {
            ids->cooldowns[idx].in_use = 1;
            snprintf(ids->cooldowns[idx].key, sizeof(ids->cooldowns[idx].key), "%s", full_key);
            ids->cooldowns[idx].last_alert_sec = now_sec;
            return 0;
        }
        if (strcmp(ids->cooldowns[idx].key, full_key) == 0) {
            if (now_sec - ids->cooldowns[idx].last_alert_sec < 10) {
                return 1; /* Suppress duplicate within 10 seconds */
            }
            ids->cooldowns[idx].last_alert_sec = now_sec;
            return 0;
        }
        if (first_expired_idx == -1 && (now_sec - ids->cooldowns[idx].last_alert_sec >= 10)) {
            first_expired_idx = idx;
        }
        if (ids->cooldowns[idx].last_alert_sec < oldest_ts) {
            oldest_ts = ids->cooldowns[idx].last_alert_sec;
            oldest_idx = idx;
        }
    }

    /* If cooldown table is completely full, recycle first expired slot or oldest slot */
    int recycle_idx = (first_expired_idx != -1) ? first_expired_idx : oldest_idx;
    ids->cooldowns[recycle_idx].in_use = 1;
    snprintf(ids->cooldowns[recycle_idx].key, sizeof(ids->cooldowns[recycle_idx].key), "%s", full_key);
    ids->cooldowns[recycle_idx].last_alert_sec = now_sec;
    return 0;
}

static void add_alert(cmonitor_alert_t *alerts, int *count, int max_alerts,
                      const cmonitor_packet_meta_t *meta, int severity,
                      const char *alert_type, const char *msg, const char *details) {
    if (*count >= max_alerts) return;
    cmonitor_alert_t *a = &alerts[*count];
    memset(a, 0, sizeof(*a));
    a->ts_sec = meta->ts_sec;
    a->ts_usec = meta->ts_usec;
    a->severity = severity;
    snprintf(a->alert_type, sizeof(a->alert_type), "%s", alert_type);
    snprintf(a->message, sizeof(a->message), "%s", msg);
    snprintf(a->src_ip, sizeof(a->src_ip), "%s", meta->src_ip);
    snprintf(a->dst_ip, sizeof(a->dst_ip), "%s", meta->dst_ip);
    a->src_port = meta->src_port;
    a->dst_port = meta->dst_port;
    snprintf(a->protocol, sizeof(a->protocol), "%s", meta->protocol);
    if (details) snprintf(a->details, sizeof(a->details), "%s", details);
    (*count)++;
}

int cmonitor_ids_analyze(cmonitor_ids_t *ids, const cmonitor_packet_meta_t *meta,
                         cmonitor_alert_t *out_alerts, int max_alerts) {
    if (!ids || !ids->cfg.enabled || !meta || !out_alerts || max_alerts <= 0) return 0;
    int alert_count = 0;
    int64_t now_sec = meta->ts_sec;

    /* 1. Blacklist / Threat Feed Matching */
    for (size_t i = 0; BLACKLIST_IPS[i] != NULL; ++i) {
        if (strcmp(meta->src_ip, BLACKLIST_IPS[i]) == 0) {
            if (!should_suppress(ids, "BLACKLISTED_IP", meta->src_ip, now_sec)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Traffic detected from known malicious/blacklisted IP: %s", meta->src_ip);
                add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_CRITICAL,
                          "BLACKLISTED_IP", msg, "threat_ip=inbound");
            }
        }
        if (strcmp(meta->dst_ip, BLACKLIST_IPS[i]) == 0) {
            if (!should_suppress(ids, "BLACKLISTED_IP", meta->dst_ip, now_sec)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Outbound connection attempt to blacklisted IP: %s", meta->dst_ip);
                add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_CRITICAL,
                          "BLACKLISTED_IP", msg, "threat_ip=outbound");
            }
        }
    }

    /* 2. Suspicious Ports Check */
    if (meta->dst_port > 0) {
        for (size_t i = 0; SUSPICIOUS_PORTS[i].desc != NULL; ++i) {
            if (SUSPICIOUS_PORTS[i].port == meta->dst_port) {
                char port_key[80];
                snprintf(port_key, sizeof(port_key), "%s:%u", meta->src_ip, meta->dst_port);
                if (!should_suppress(ids, "SUSPICIOUS_PORT", port_key, now_sec)) {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "Connection targeting suspicious port %u (%s) from %s",
                             meta->dst_port, SUSPICIOUS_PORTS[i].desc, meta->src_ip);
                    add_alert(out_alerts, &alert_count, max_alerts, meta, SUSPICIOUS_PORTS[i].severity,
                              "SUSPICIOUS_PORT", msg, SUSPICIOUS_PORTS[i].desc);
                }
                break;
            }
        }
    }

    /* 3. Stealth Scans */
    if (strcmp(meta->protocol, "TCP") == 0) {
        uint8_t f = meta->tcp_flags;
        /* Xmas scan: FIN + PSH + URG */
        if ((f & CMONITOR_TCP_FIN) && (f & CMONITOR_TCP_PSH) && (f & CMONITOR_TCP_URG)) {
            if (!should_suppress(ids, "XMAS_SCAN", meta->src_ip, now_sec)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "TCP Xmas stealth scan packet detected from %s", meta->src_ip);
                add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_HIGH,
                          "XMAS_SCAN", msg, "flags=FIN,PSH,URG");
            }
        }
        /* Null scan: No flags set */
        else if (f == 0) {
            if (!should_suppress(ids, "NULL_SCAN", meta->src_ip, now_sec)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "TCP Null stealth scan packet detected from %s", meta->src_ip);
                add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_HIGH,
                          "NULL_SCAN", msg, "flags=none");
            }
        }
        /* FIN scan: Only FIN is set */
        else if (f == CMONITOR_TCP_FIN) {
            if (!should_suppress(ids, "FIN_SCAN", meta->src_ip, now_sec)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "TCP FIN stealth scan packet detected from %s", meta->src_ip);
                add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_HIGH,
                          "FIN_SCAN", msg, "flags=FIN");
            }
        }
    }

    /* 4. ARP Spoofing / MITM Poisoning Detection */
    if (strcmp(meta->protocol, "ARP") == 0 && meta->src_ip[0] != '\0' &&
        strcmp(meta->src_ip, "0.0.0.0") != 0 && strcmp(meta->src_ip, "unknown") != 0) {

        int found_idx = -1;
        int empty_idx = -1;
        int oldest_idx = 0;
        int64_t oldest_ts = ids->arp_table[0].last_seen_sec;

        for (int i = 0; i < MAX_ARP_ENTRIES; i++) {
            if (ids->arp_table[i].in_use) {
                if (strcmp(ids->arp_table[i].ip, meta->src_ip) == 0) {
                    found_idx = i;
                    break;
                }
                if (ids->arp_table[i].last_seen_sec < oldest_ts) {
                    oldest_ts = ids->arp_table[i].last_seen_sec;
                    oldest_idx = i;
                }
            } else if (empty_idx == -1) {
                empty_idx = i;
            }
        }

        if (found_idx == -1) {
            int target_idx = (empty_idx != -1) ? empty_idx : oldest_idx;
            snprintf(ids->arp_table[target_idx].ip, sizeof(ids->arp_table[target_idx].ip), "%s", meta->src_ip);
            snprintf(ids->arp_table[target_idx].mac, sizeof(ids->arp_table[target_idx].mac), "%s", meta->src_mac);
            ids->arp_table[target_idx].last_seen_sec = now_sec;
            ids->arp_table[target_idx].in_use = 1;
        } else {
            if (strcasecmp(ids->arp_table[found_idx].mac, meta->src_mac) != 0 &&
                strcmp(meta->src_mac, "ff:ff:ff:ff:ff:ff") != 0 &&
                strcmp(meta->src_mac, "00:00:00:00:00:00") != 0) {

                if (!should_suppress(ids, "ARP_SPOOFING", meta->src_ip, now_sec)) {
                    char msg[256];
                    char det[256];
                    snprintf(msg, sizeof(msg),
                             "ARP spoofing / MITM detected: IP %s claimed by MAC %s (conflicts with known MAC %s)",
                             meta->src_ip, meta->src_mac, ids->arp_table[found_idx].mac);
                    snprintf(det, sizeof(det), "mitm=arp_cache_poisoning known_mac=%s rogue_mac=%s",
                             ids->arp_table[found_idx].mac, meta->src_mac);
                    add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_CRITICAL,
                              "ARP_SPOOFING", msg, det);
                }
            } else {
                ids->arp_table[found_idx].last_seen_sec = now_sec;
            }
        }

        if (meta->arp_opcode == 2 && strcmp(meta->src_ip, meta->dst_ip) == 0) {
            if (!should_suppress(ids, "GRATUITOUS_ARP", meta->src_ip, now_sec)) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "Gratuitous ARP reply broadcast from %s (%s): potential cache poisoning attempt",
                         meta->src_ip, meta->src_mac);
                add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_HIGH,
                          "GRATUITOUS_ARP", msg, "gratuitous_arp=reply_broadcast");
            }
        }
    }

    host_tracker_t *tracker = get_host_tracker(ids, meta->src_ip);
    if (!tracker) return alert_count;

    /* 4. Port Scan (SYN Scan) */
    if (strcmp(meta->protocol, "TCP") == 0 &&
        (meta->tcp_flags & CMONITOR_TCP_SYN) &&
        !(meta->tcp_flags & CMONITOR_TCP_ACK) &&
        meta->dst_port > 0) {

        int slot = tracker->port_head;
        tracker->port_events[slot].ts_sec = now_sec;
        tracker->port_events[slot].port = meta->dst_port;
        tracker->port_head = (slot + 1) % MAX_PORT_EVENTS;
        if (tracker->port_count < MAX_PORT_EVENTS) tracker->port_count++;

        /* Count distinct probed ports within port_scan_window_sec */
        uint16_t probed[MAX_PORT_EVENTS];
        int distinct_count = 0;
        int64_t cutoff = now_sec - ids->cfg.port_scan_window_sec;

        for (int i = 0; i < tracker->port_count; ++i) {
            if (tracker->port_events[i].ts_sec >= cutoff) {
                uint16_t p = tracker->port_events[i].port;
                int found = 0;
                for (int j = 0; j < distinct_count; ++j) {
                    if (probed[j] == p) { found = 1; break; }
                }
                if (!found && distinct_count < MAX_PORT_EVENTS) {
                    probed[distinct_count++] = p;
                }
            }
        }

        if (distinct_count >= ids->cfg.port_scan_threshold) {
            if (!should_suppress(ids, "PORT_SCAN_SYN", meta->src_ip, now_sec)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Port scan detected from %s: %d distinct ports probed in %ds",
                         meta->src_ip, distinct_count, ids->cfg.port_scan_window_sec);
                add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_HIGH,
                          "PORT_SCAN_SYN", msg, "scan=SYN");
            }
        }

        /* 5. SYN Flood */
        int s_slot = tracker->syn_head;
        tracker->syn_events[s_slot] = now_sec;
        tracker->syn_head = (s_slot + 1) % MAX_SYN_EVENTS;
        if (tracker->syn_count < MAX_SYN_EVENTS) tracker->syn_count++;

        int active_syns = 0;
        int64_t syn_cutoff = now_sec - ids->cfg.syn_flood_window_sec;
        for (int i = 0; i < tracker->syn_count; ++i) {
            if (tracker->syn_events[i] >= syn_cutoff) active_syns++;
        }

        if (active_syns >= ids->cfg.syn_flood_threshold) {
            if (!should_suppress(ids, "SYN_FLOOD", meta->src_ip, now_sec)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "TCP SYN flood detected from %s: %d SYNs in %ds",
                         meta->src_ip, active_syns, ids->cfg.syn_flood_window_sec);
                add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_CRITICAL,
                          "SYN_FLOOD", msg, "flood=SYN");
            }
        }
    }

    /* 6. ICMP / ICMPv6 Ping Flood */
    if (strcmp(meta->protocol, "ICMP") == 0 || strcmp(meta->protocol, "ICMPv6") == 0) {
        int ic_slot = tracker->icmp_head;
        tracker->icmp_events[ic_slot] = now_sec;
        tracker->icmp_head = (ic_slot + 1) % MAX_ICMP_EVENTS;
        if (tracker->icmp_count < MAX_ICMP_EVENTS) tracker->icmp_count++;

        int win_sec = ids->cfg.icmp_flood_window_sec > 0 ? ids->cfg.icmp_flood_window_sec : 2;
        int64_t icmp_cutoff = now_sec - win_sec;
        int active_icmps = 0;
        for (int i = 0; i < tracker->icmp_count; ++i) {
            if (tracker->icmp_events[i] >= icmp_cutoff) active_icmps++;
        }

        int thresh = ids->cfg.icmp_flood_threshold > 0 ? ids->cfg.icmp_flood_threshold : 50;
        if (active_icmps >= thresh) {
            if (!should_suppress(ids, "ICMP_FLOOD", meta->src_ip, now_sec)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "%s ping flood detected from %s (%d packets in %ds)",
                         meta->protocol, meta->src_ip, active_icmps, win_sec);
                add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_HIGH,
                          "ICMP_FLOOD", msg, "flood=ICMP");
            }
        }
    }

    /* 7. Bandwidth Spike */
    int b_slot = tracker->bw_head;
    tracker->bw_events[b_slot].ts_sec = now_sec;
    tracker->bw_events[b_slot].bytes = meta->packet_size;
    tracker->bw_head = (b_slot + 1) % MAX_BW_EVENTS;
    if (tracker->bw_count < MAX_BW_EVENTS) tracker->bw_count++;

    size_t total_b = 0;
    int64_t b_cutoff = now_sec - ids->cfg.bw_window_sec;
    for (int i = 0; i < tracker->bw_count; ++i) {
        if (tracker->bw_events[i].ts_sec >= b_cutoff) {
            total_b += tracker->bw_events[i].bytes;
        }
    }

    size_t rate_bps = total_b / (ids->cfg.bw_window_sec > 0 ? ids->cfg.bw_window_sec : 1);
    if (rate_bps >= ids->cfg.bw_spike_bytes_sec) {
        if (!should_suppress(ids, "BANDWIDTH_SPIKE", meta->src_ip, now_sec)) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Bandwidth spike detected from %s: %.2f MB/s",
                     meta->src_ip, (double)rate_bps / (1024.0 * 1024.0));
            add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_MEDIUM,
                      "BANDWIDTH_SPIKE", msg, "bandwidth_spike");
        }
    }

    /* 8. DNS Tunneling Anomaly */
    size_t qlen = strlen(meta->dns_query);
    if (qlen > ids->cfg.dns_tunnel_len) {
        if (!should_suppress(ids, "DNS_TUNNEL_ANOMALY", meta->dns_query, now_sec)) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Abnormally long DNS query detected (%zu chars): potential DNS tunneling or exfiltration", qlen);
            add_alert(out_alerts, &alert_count, max_alerts, meta, CMONITOR_SEV_HIGH,
                      "DNS_TUNNEL_ANOMALY", msg, meta->dns_query);
        }
    }

    return alert_count;
}
