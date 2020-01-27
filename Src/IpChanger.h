#pragma once

#include <string>
#include "NetfilterManager.h"
#include "IpFlowManager.h"
#include "pol4b_ip.h"

namespace pol4b {
class IpChanger
{
public:
    #define ACCEPT_AND_THROW(x) nfq_set_verdict(queue_handle, ntohl(packet_header->packet_id), NF_ACCEPT, 0, nullptr); throw x
    using OnError = std::function<void(int)>;
    using OnInfo = std::function<void(std::string)>;

    IpChanger();
    IpChanger(OnError cb_on_error_in, OnInfo cb_on_info_in);

private:
    static int cb_input(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data);
    static int cb_output(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data);

public:
    bool is_started();
    void set_cb_on_error(OnError cb_on_error_in);
    void set_cb_on_info(OnInfo cb_on_info_in);

    void start(uint16_t input_queue, uint16_t output_queue, Ip dst_ip, uint16_t dst_port);

private:
    IpPortPair destination;
    IpFlowManager flow_manager;
    NetfilterManager input_netfilter_manager;
    NetfilterManager output_netfilter_manager;

private:
    OnError cb_on_error;
    OnInfo cb_on_info;

    void on_error(int error_code);
    void on_info(std::string message);
};
}
