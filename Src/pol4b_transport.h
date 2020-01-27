#pragma once

#include "pol4b_ip.h"

namespace pol4b {
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
