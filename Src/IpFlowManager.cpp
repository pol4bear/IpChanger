#include "IpFlowManager.h"

using namespace std;
using namespace chrono;

namespace pol4b {
IpFlowManager::IpFlowManager() {}

void IpFlowManager::assign_input(uint8_t *packet) {
    iphdr *ip_header = (iphdr*)packet;
    FlowValue *value;
    IpPortPair src, dst;

    if (ip_header->protocol == IPPROTO_TCP) {
        tcphdr *tcp_header = TcpUtil::get_tcp_header(ip_header);
        dst = IpPortPair(ip_header->daddr, ntohs(tcp_header->dest));
        value = &flow_map[dst];

        if (tcp_header->syn) {
            if (value->state == State::TCP_SYN) value->state = State::TCP_ESTABLISHED;
            else value->state = State::TCP_SYN_RECEIVED;
        }
        else if (tcp_header->fin) {
            if (value->state == State::TCP_FIN_WAIT) value->state = State::TCP_TIME_WAIT;
            else value->state = State::TCP_CLOSE_WAIT;
        }
        else if (tcp_header->rst) {
            value->state = State::TCP_CLOSE;
        }
        else if (tcp_header->ack) {
            if (value->state != TCP_TIME_WAIT) value->state = State::TCP_ESTABLISHED;
        }
    }
    else if(ip_header->protocol == IPPROTO_UDP) {
        udphdr *udp_header = UdpUtil::get_udp_header(ip_header);
        dst = IpPortPair(ip_header->daddr, udp_header->dest);
        value = &flow_map[dst];

        if (value->state == State::UDP) value->state = State::UDP_STREAM;
        else value->state = State::UDP;
    }
    else return;

    value->last_communication = system_clock::now();
}

void IpFlowManager::assign_output(uint8_t *packet) {
    iphdr *ip_header = (iphdr*)packet;
    FlowValue *value;
    IpPortPair src, dst;

    if (ip_header->protocol == IPPROTO_TCP) {
        tcphdr *tcp_header = TcpUtil::get_tcp_header(ip_header);
        src = IpPortPair(ip_header->saddr, ntohs(tcp_header->source));
        dst = IpPortPair(ip_header->daddr, ntohs(tcp_header->dest));
        value = &flow_map[src];

        if (tcp_header->syn) {
            if (value->state == State::TCP_SYN_RECEIVED) value->state = State::TCP_ESTABLISHED;
            else value->state = State::TCP_SYN;
        }
        else if (tcp_header->fin) {
            if (value->state == State::TCP_CLOSE_WAIT) value->state = State::TCP_LAST_ACK;
            else value->state = State::TCP_FIN_WAIT;
        }
        else if (tcp_header->rst) {
            value->state = State::TCP_CLOSE;
        }
        else if (tcp_header->ack) {
            if (value->state == TCP_LAST_ACK) value->state = State::TCP_CLOSE;
            else value->state = State::TCP_ESTABLISHED;
        }
    }
    else if(ip_header->protocol == IPPROTO_UDP) {
        udphdr *udp_header = UdpUtil::get_udp_header(ip_header);
        src = IpPortPair(ip_header->saddr, udp_header->source);
        dst = IpPortPair(ip_header->daddr, udp_header->dest);
        value = &flow_map[src];

        if (value->state == State::UDP) value->state = State::UDP_STREAM;
        else value->state = State::UDP;
    }
    else return;

    value->value = dst;
    value->last_communication = system_clock::now();
}

bool IpFlowManager::get_original_destination(IpPortPair original_source, IpPortPair &original_destination) {
    auto found = flow_map.find(original_source);
    if(found == flow_map.end()) return false;
    original_destination = found->second.value;
    return true;
}
}
