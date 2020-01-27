#pragma once

#include "FlowManager.h"
#include "pol4b_tcp.h"
#include "pol4b_udp.h"

namespace pol4b {
class IpFlowManager : public FlowManager<IpPortPair, IpPortPair>
{
public:
    IpFlowManager();

    void assign_input(uint8_t *packet) override;
    void assign_output(uint8_t *packet) override;

    bool get_original_destination(IpPortPair original_source, IpPortPair &original_destination);
};
}

