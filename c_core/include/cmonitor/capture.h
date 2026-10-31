#ifndef CMONITOR_CAPTURE_H
#define CMONITOR_CAPTURE_H

#include "cmonitor/packet.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cmonitor_capture cmonitor_capture_t;

cmonitor_capture_t* cmonitor_capture_open_live(const char *device, const char *bpf_filter,
                                               int promisc, int snaplen, char *errbuf);

cmonitor_capture_t* cmonitor_capture_open_offline(const char *filepath, const char *bpf_filter,
                                                  char *errbuf);

int cmonitor_capture_next(cmonitor_capture_t *cap, cmonitor_packet_meta_t *out_meta,
                          const uint8_t **out_raw_data, uint32_t *out_raw_len);

void cmonitor_capture_close(cmonitor_capture_t *cap);

#ifdef __cplusplus
}
#endif

#endif /* CMONITOR_CAPTURE_H */
