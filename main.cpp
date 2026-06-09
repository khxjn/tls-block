#include <cstdio>
#include <iostream>
#include <string>
#include <pcap.h>
#include "struct_hdr.h"
#include "tls-block.h"
#include "tls-parser.h"

void usage() {
    printf("syntax: ./tls-block <interface> <server name>\n");
    printf("sample: ./tls-block wlan0 naver.com\n");
}

int main(int argc, char* argv[]) {
    if(argc != 3) {
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    if(!get_mac(argv[1], &my_mac)) return -1;

    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 10, errbuf);
    if(!handle) return -1;

    struct pcap_pkthdr* header;
    const u_char* packet;

    while(pcap_next_ex(handle, &header, &packet) >= 0) {
        Eth_hdr* eth = (Eth_hdr*)packet;
        if(ntohs(eth->type) != 0x0800) continue;

        Ipv4_hdr* ip = (Ipv4_hdr*)(packet + sizeof(Eth_hdr));
        if(ip->protocol != 0x06 || ip->is_fragmented()) continue;

        Tcp_hdr* tcp = (Tcp_hdr*)(packet + sizeof(Eth_hdr) + ip->get_ihl());
        int data_len = ntohs(ip->ip_tot_len) - ip->get_ihl() - tcp->get_header_len();
        if(data_len <= 0) continue;

        const u_char* payload = packet + sizeof(Eth_hdr) + ip->get_ihl() + tcp->get_header_len();
        std::string sni;

        if(process_tls_segment(packet, payload, data_len, sni)) {
            if(sni == argv[2]) {
                printf("SNI: %s -> Blocked!\n", sni.c_str());
                send_rst(packet, handle);
                send_backward_rst(packet);
            }
        }
    }
    pcap_close(handle);
    return 0;
}