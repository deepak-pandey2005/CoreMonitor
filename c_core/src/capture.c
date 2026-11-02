#include "cmonitor/capture.h"
#include "cmonitor/parser.h"
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

struct cmonitor_capture {
    pcap_t *handle;
    int is_offline;
};

static int apply_bpf(pcap_t *handle, const char *bpf_filter, char *errbuf) {
    if (!bpf_filter || strlen(bpf_filter) == 0) return 0;
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, bpf_filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "BPF compile error: %s", pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "BPF setfilter error: %s", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

cmonitor_capture_t* cmonitor_capture_open_live(const char *device, const char *bpf_filter,
                                               int promisc, int snaplen, char *errbuf) {
    char local_errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_open_live(device, snaplen, promisc, 1000, local_errbuf);
    if (!handle) {
        if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", local_errbuf);
        return NULL;
    }

    if (apply_bpf(handle, bpf_filter, errbuf) != 0) {
        pcap_close(handle);
        return NULL;
    }

    cmonitor_capture_t *cap = (cmonitor_capture_t*)calloc(1, sizeof(cmonitor_capture_t));
    if (!cap) {
        pcap_close(handle);
        return NULL;
    }
    cap->handle = handle;
    cap->is_offline = 0;
    return cap;
}

cmonitor_capture_t* cmonitor_capture_open_offline(const char *filepath, const char *bpf_filter,
                                                  char *errbuf) {
    char local_errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_open_offline(filepath, local_errbuf);
    if (!handle) {
        if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", local_errbuf);
        return NULL;
    }

    if (apply_bpf(handle, bpf_filter, errbuf) != 0) {
        pcap_close(handle);
        return NULL;
    }

    cmonitor_capture_t *cap = (cmonitor_capture_t*)calloc(1, sizeof(cmonitor_capture_t));
    if (!cap) {
        pcap_close(handle);
        return NULL;
    }
    cap->handle = handle;
    cap->is_offline = 1;
    return cap;
}

int cmonitor_capture_next(cmonitor_capture_t *cap, cmonitor_packet_meta_t *out_meta,
                          const uint8_t **out_raw_data, uint32_t *out_raw_len) {
    if (!cap || !cap->handle) return -1;

    struct pcap_pkthdr *header = NULL;
    const u_char *pkt_data = NULL;

    int res = pcap_next_ex(cap->handle, &header, &pkt_data);
    if (res == 1) {
        if (out_raw_data) *out_raw_data = pkt_data;
        if (out_raw_len) *out_raw_len = header->caplen;

        if (out_meta) {
            cmonitor_parse_packet(pkt_data, header->caplen, header->len,
                                  header->ts.tv_sec, header->ts.tv_usec, out_meta);
        }
        return 1; /* Success */
    } else if (res == 0) {
        return 0; /* Live timeout, no packet received */
    } else if (res == -2) {
        return -2; /* EOF reached on offline pcap */
    } else {
        return -1; /* Error */
    }
}

int cmonitor_capture_set_bpf(cmonitor_capture_t *cap, const char *bpf_filter, char *errbuf) {
    if (!cap || !cap->handle) {
        if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "Capture handle is null");
        return -1;
    }
    if (!bpf_filter || strlen(bpf_filter) == 0) {
        struct bpf_program fp;
        if (pcap_compile(cap->handle, &fp, "", 1, PCAP_NETMASK_UNKNOWN) == 0) {
            if (pcap_setfilter(cap->handle, &fp) == -1) {
                if (errbuf) snprintf(errbuf, PCAP_ERRBUF_SIZE, "BPF clear filter error: %s", pcap_geterr(cap->handle));
                pcap_freecode(&fp);
                return -1;
            }
            pcap_freecode(&fp);
        }
        return 0;
    }
    return apply_bpf(cap->handle, bpf_filter, errbuf);
}

void cmonitor_capture_close(cmonitor_capture_t *cap) {
    if (!cap) return;
    if (cap->handle) {
        pcap_close(cap->handle);
        cap->handle = NULL;
    }
    free(cap);
}
