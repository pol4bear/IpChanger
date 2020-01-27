#include "pol4b_transport.h"

namespace pol4b {
IpPortPair::IpPortPair() {}
IpPortPair::IpPortPair(Ip ip_in, uint16_t port_in) : ip(ip_in), port(port_in) {}

bool IpPortPair::operator<(const IpPortPair &rhs) const { return ip < rhs.ip && port < rhs.port; }
}
