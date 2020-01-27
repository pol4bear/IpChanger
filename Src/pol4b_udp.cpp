#include "pol4b_udp.h"

uint16_t pol4b::UdpUtil::get_udp_checksum(iphdr *ip_header, udphdr *udp_header, uint32_t packet_length) {
    uint32_t sum = 0;
    uint32_t udp_length = packet_length - ip_header->ihl * 4;

    udp_header->check = 0;
    sum += (ip_header->saddr >> 16) & 0xFFFF;
    sum += (ip_header->saddr) & 0xFFFF;
    sum += (ip_header->daddr >> 16) & 0xFFFF;
    sum += (ip_header->daddr) & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += htons(udp_length);

    return NetworkUtil::compute_checksum(sum, (uint16_t *)udp_header, udp_length);
}

udphdr *pol4b::UdpUtil::get_udp_header(iphdr *ip_header) { return (udphdr*)((uint8_t*)ip_header + ip_header->ihl * 4); }

uint8_t *pol4b::UdpUtil::get_udp_payload(udphdr *udp_header, uint8_t *packet_tail) {
    uint8_t *payload_entry = (uint8_t*)udp_header + sizeof(udphdr);
    if (payload_entry > packet_tail) return nullptr;
    return payload_entry;
}

uint32_t pol4b::UdpUtil::get_udp_payload_length(udphdr *udp_header) { return ntohs(udp_header->len) - sizeof(udphdr); }
