#include "pol4b_transport.h"

namespace pol4b {
IpPortPair::IpPortPair() {}
IpPortPair::IpPortPair(Ip ip_in, uint16_t port_in) : ip(ip_in), port(port_in) {}

bool IpPortPair::operator<(const IpPortPair &rhs) const { return ip < rhs.ip && port < rhs.port; }

uint16_t TransportUtil::get_tcp_udp_checksum(iphdr *ip_header, uint8_t *transport_header, uint16_t protocol, uint32_t packet_length) {
    uint32_t sum = 0;
    uint32_t transport_length = packet_length - ip_header->ihl * 4;


    sum += (ip_header->saddr >> 16) & 0xFFFF;
    sum += (ip_header->saddr) & 0xFFFF;
    sum += (ip_header->daddr >> 16) & 0xFFFF;
    sum += (ip_header->daddr) & 0xFFFF;
    sum += htons(protocol);
    sum += htons(transport_length);

    return NetworkUtil::compute_checksum(sum, (uint16_t *)transport_header, transport_length);
}

}
