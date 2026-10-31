#ifndef CMONITOR_PARSER_H
#define CMONITOR_PARSER_H

#include "cmonitor/packet.h"

#ifdef __cplusplus
extern "C" {
#endif

int cmonitor_parse_packet(const uint8_t *data, uint32_t caplen, uint32_t len,
                          int64_t sec, int64_t usec, cmonitor_packet_meta_t *out_meta);

const char* cmonitor_get_service_name(uint16_t port);

#ifdef __cplusplus
}
#endif

#endif /* CMONITOR_PARSER_H */
