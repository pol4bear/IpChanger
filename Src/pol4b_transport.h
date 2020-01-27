#pragma once

#include "pol4b_ip.h"

namespace pol4b {
class TransportUtil {
public:
    static uint16_t get_tcp_udp_checksum(iphdr *ip_header, uint8_t *transport_header, uint16_t protocol, uint32_t packet_length);
};

class IpPortPair {
public:
    IpPortPair();
    IpPortPair(Ip ip_in, uint16_t port_in);

    Ip ip;
    uint16_t port;

public:
    bool operator<(const IpPortPair &rhs) const;
};
}
