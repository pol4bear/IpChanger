#include "IpChanger.h"

using namespace std;

namespace pol4b {
IpChanger::IpChanger() : cb_on_error(nullptr), cb_on_info(nullptr) {}
IpChanger::IpChanger(OnError cb_on_error_in, OnInfo cb_on_info_in) : cb_on_error(cb_on_error_in), cb_on_info(cb_on_info_in) {}

int IpChanger::cb_input(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data) {
    IpChanger *handle = (IpChanger*)data;

    nfqnl_msg_packet_hdr *packet_header = nfq_get_msg_packet_hdr(netfilter_data);
    if (packet_header == nullptr) { ACCEPT_AND_THROW(NetfilterManager::Error::NFQ_GET_PACKET_HEADER); }

    uint8_t *packet = nullptr;
    int packet_length = nfq_get_payload(netfilter_data, &packet);
    if (packet_length < 0) { ACCEPT_AND_THROW(NetfilterManager::Error::NFQ_GET_PAYLOAD); }
    else if (ntohs(packet_header->hw_protocol) != ETHERTYPE_IP) return nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, 0, nullptr);

    iphdr *ip_header = (iphdr*)packet;
    uint16_t *src_port = nullptr, *check = nullptr;
    if (ip_header->protocol == IPPROTO_TCP) {
        tcphdr *tcp_header = TcpUtil::get_tcp_header(ip_header);
        src_port = &tcp_header->source;
        check = &tcp_header->check;
    }
    else if(ip_header->protocol == IPPROTO_UDP) {
        udphdr *udp_header = UdpUtil::get_udp_header(ip_header);
        src_port = &udp_header->source;
        check = &udp_header->check;
    }
    else return nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, 0, nullptr);

    if (ip_header->saddr != handle->destination.ip || *src_port != handle->destination.port) return nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, 0, nullptr);
    handle->flow_manager.assign_input(packet);

    IpPortPair origin(ip_header->saddr, ntohs(*src_port));
    IpPortPair destination;
    if (handle->flow_manager.get_original_destination(origin, destination)) {
        ip_header->daddr = destination.ip;
        *src_port = htons(destination.port);
        ip_header->check = IpUtil::get_ip_checksum(ip_header);
        *check = TransportUtil::get_tcp_udp_checksum(ip_header, packet + ip_header->ihl * 4, ip_header->protocol, packet_length);
    }

    stringstream info_message;
    info_message <<"[Input] Source Changed " << origin.ip.to_string() << ":" << to_string(origin.port) << " -> " << destination.ip.to_string() << ":" << to_string(destination.port);
    handle->on_info(info_message.str());

    return nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, packet_length, packet);
}

int IpChanger::cb_output(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data) {
    IpChanger *handle = (IpChanger*)data;

    nfqnl_msg_packet_hdr *packet_header = nfq_get_msg_packet_hdr(netfilter_data);
    if (packet_header == nullptr) { ACCEPT_AND_THROW(NetfilterManager::Error::NFQ_GET_PACKET_HEADER); }

    uint8_t *packet = nullptr;
    int packet_length = nfq_get_payload(netfilter_data, &packet);
    if (packet_length < 0) { ACCEPT_AND_THROW(NetfilterManager::Error::NFQ_GET_PAYLOAD); }
    else if (ntohs(packet_header->hw_protocol) != ETHERTYPE_IP) return nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, 0, nullptr);

    iphdr *ip_header = (iphdr*)packet;
    uint16_t *dst_port = nullptr, *check = nullptr;
    if (ip_header->protocol == IPPROTO_TCP) {
        tcphdr *tcp_header = TcpUtil::get_tcp_header(ip_header);
        dst_port = &tcp_header->dest;
        check = &tcp_header->check;
    }
    else if(ip_header->protocol == IPPROTO_UDP) {
        udphdr *udp_header = UdpUtil::get_udp_header(ip_header);
        dst_port = &udp_header->dest;
        check = &udp_header->check;
    }
    else return nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, 0, nullptr);


    IpPortPair origin(ip_header->daddr, ntohs(*dst_port));
    handle->flow_manager.assign_output(packet);
    ip_header->daddr = handle->destination.ip;
    *dst_port = htons(handle->destination.port);
    ip_header->check = IpUtil::get_ip_checksum(ip_header);
    *check = TransportUtil::get_tcp_udp_checksum(ip_header, packet + ip_header->ihl * 4, ip_header->protocol, packet_length);

    stringstream info_message;
    info_message <<"[Output] Destination Changed " << origin.ip.to_string() << ":" << to_string(origin.port) << " -> " << handle->destination.ip.to_string() << ":" << to_string(handle->destination.port);
    handle->on_info(info_message.str());

    return nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, packet_length, packet);
}

bool IpChanger::is_started() { return input_netfilter_manager.is_started() && output_netfilter_manager.is_started(); }
void IpChanger::set_cb_on_error(OnError cb_on_error_in)  { cb_on_error = cb_on_error_in; }
void IpChanger::set_cb_on_info(IpChanger::OnInfo cb_on_info_in) { cb_on_info = cb_on_info_in; }

void IpChanger::start(uint16_t input_queue, uint16_t output_queue, Ip dst_ip, uint16_t dst_port) {
    if (is_started()) on_error(NetfilterManager::Error::ALREADY_STARTED);

    destination = IpPortPair(dst_ip, dst_port);

    try {
        input_netfilter_manager.start(input_queue, cb_input, this);
        output_netfilter_manager.start(output_queue, cb_output, this);
    } catch(NetfilterManager::Error::Code error_code) { on_error(error_code); }
}

void IpChanger::on_error(int error_code) { if (cb_on_error != nullptr) cb_on_error(error_code); }
void IpChanger::on_info(std::string message) { if (cb_on_info != nullptr) cb_on_info(message); }
}
