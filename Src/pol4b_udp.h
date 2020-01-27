#pragma once

#include <netinet/ip.h>
#include <netinet/udp.h>
#include "pol4b_transport.h"
#include "pol4b_util.h"

namespace pol4b {
class UdpUtil {
public:
    static uint16_t get_udp_checksum(iphdr *ip_header, udphdr *udp_header, uint32_t packet_length);
    static udphdr *get_udp_header(iphdr *ip_header);
    static uint8_t *get_udp_payload(udphdr *udp_header, uint8_t *packet_tail);
    static uint32_t get_udp_payload_length(udphdr *udp_header);
};
}
