#include "tls-block.h"
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

Mac my_mac;

uint16_t calc_checksum(uint16_t* data, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t*)data;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

void make_rst_packet(const u_char* origin, std::vector<uint8_t>& pkt, bool is_back) {
    Eth_hdr* o_eth = (Eth_hdr*)origin;
    Ipv4_hdr* o_ip = (Ipv4_hdr*)(origin + sizeof(Eth_hdr));
    Tcp_hdr* o_tcp = (Tcp_hdr*)(origin + sizeof(Eth_hdr) + o_ip->get_ihl());

    int data_len = ntohs(o_ip->ip_tot_len) - o_ip->get_ihl() - o_tcp->get_header_len();
    pkt.resize(sizeof(Eth_hdr) + sizeof(Ipv4_hdr) + sizeof(Tcp_hdr), 0);

    Eth_hdr* eth = (Eth_hdr*)pkt.data();
    Ipv4_hdr* ip = (Ipv4_hdr*)(pkt.data() + sizeof(Eth_hdr));
    Tcp_hdr* tcp = (Tcp_hdr*)(pkt.data() + sizeof(Eth_hdr) + sizeof(Ipv4_hdr));

    eth->smac = my_mac;
    eth->dmac = is_back ? o_eth->smac : o_eth->dmac;
    eth->type = htons(0x0800);

    ip->set_version(4, 5);
    ip->tos = 0;
    ip->identification = 0;
    ip->frag_offset = 0;
    ip->ttl = 128;
    ip->protocol = 6;
    ip->ip_tot_len = htons(sizeof(Ipv4_hdr) + sizeof(Tcp_hdr));
    ip->sip = is_back ? o_ip->dip : o_ip->sip;
    ip->dip = is_back ? o_ip->sip : o_ip->dip;
    ip->ip_checksum = 0;
    ip->ip_checksum = calc_checksum((uint16_t*)ip, sizeof(Ipv4_hdr));

    tcp->tcp_src = is_back ? o_tcp->tcp_dst : o_tcp->tcp_src;
    tcp->tcp_dst = is_back ? o_tcp->tcp_src : o_tcp->tcp_dst;
    tcp->seq_num = is_back ? o_tcp->ack_num : htonl(ntohl(o_tcp->seq_num) + data_len);
    tcp->ack_num = is_back ? htonl(ntohl(o_tcp->seq_num) + data_len) : o_tcp->ack_num;
    tcp->set_offset(5);
    tcp->tcp_flags = 0x04 | 0x10; // RST | ACK
    tcp->window = 0;
    tcp->urg_ptr = 0;
    tcp->tcp_checksum = 0;

    Pseudo_hdr psh;
    psh.sip = ip->sip;
    psh.dip = ip->dip;
    psh.reserved = 0;
    psh.protocol = 6;
    psh.tcp_len = htons(sizeof(Tcp_hdr));

    std::vector<uint8_t> pseudo(sizeof(Pseudo_hdr) + sizeof(Tcp_hdr), 0);
    memcpy(pseudo.data(), &psh, sizeof(Pseudo_hdr));
    memcpy(pseudo.data() + sizeof(Pseudo_hdr), tcp, sizeof(Tcp_hdr));
    tcp->tcp_checksum = calc_checksum((uint16_t*)pseudo.data(), pseudo.size());
}

void send_rst(const u_char* origin, pcap_t* handle) {
    std::vector<uint8_t> pkt;
    make_rst_packet(origin, pkt, false);
    pcap_sendpacket(handle, pkt.data(), pkt.size());
}

void send_backward_rst(const u_char* origin) {
    std::vector<uint8_t> pkt;
    make_rst_packet(origin, pkt, true);
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ((Ipv4_hdr*)(pkt.data() + sizeof(Eth_hdr)))->dip;
    
    sendto(sock, pkt.data() + sizeof(Eth_hdr), pkt.size() - sizeof(Eth_hdr), 0, (struct sockaddr*)&sin, sizeof(sin));
    close(sock);
}

bool get_mac(const char* dev, Mac* mac_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return false; }
    close(fd);
    memcpy(mac_addr->mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}