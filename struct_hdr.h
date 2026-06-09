#ifndef STRUCT_HDR_H
#define STRUCT_HDR_H

#include <cstdint>
#include <cstddef>
#include <arpa/inet.h> 

#pragma pack(push, 1)
struct Mac {
    uint8_t mac[6];
};

struct Eth_hdr {
    Mac dmac;
    Mac smac; 
    uint16_t type;  
};

struct Arp_hdr {
    uint16_t htype;     // Hardware Type (Ethernet == 1)
    uint16_t ptype;     // Protocol Type (IPv4 == 0x0800)
    uint8_t hlen;       // Hardware Length (Ehternet == 6)
    uint8_t plen;       // Protocol Length (Ipv4 == 4)
    uint16_t op;        // Operation (1 == request, 2 == reply)
    Mac smac;           // Sender MAC 
    uint32_t sip;       // Sender IP
    Mac tmac;           // Target MAC
    uint32_t tip;       // Target IP
};

struct Ipv4_hdr {
    uint8_t ip_hl;              // Version(4) + IHL(4)
    uint8_t tos;                // Type of Service
    uint16_t ip_tot_len;        // IP Datagram Total length
    uint16_t identification;    // Identification
    uint16_t frag_offset;       // IP flags(3) + Fragment offset(13)
    uint8_t ttl;                // Time To Live
    uint8_t protocol;           // Protocol
    uint16_t ip_checksum;       // Header Checksum
    uint32_t sip;               // Source Address
    uint32_t dip;               // Destination Address

    void set_version(uint8_t version, uint8_t ihl) {
        this->ip_hl = (version << 4) | (ihl & 0x0F);
    }

    int get_ihl() {
        return (this->ip_hl & 0x0F) * 4;
    }

    bool is_fragmented() {
        return (ntohs(this->frag_offset) & 0x3fff) != 0;
    }
};

struct Tcp_hdr {
    uint16_t tcp_src;           // Source Port
    uint16_t tcp_dst;           // Destionation Port
    uint32_t seq_num;           // Sequence Number
    uint32_t ack_num;           // Acknowledgement Number
    uint8_t tcp_hl;             // Offset(4) + Reserved(4)
    uint8_t tcp_flags;          // TCP Flags
    uint16_t window;            // Window
    uint16_t tcp_checksum;      // Checksum
    uint16_t urg_ptr;           // Urgent Pointer

    void set_offset(uint8_t offset) {
        this->tcp_hl = (offset << 4) & 0xF0; 
    }

    int get_header_len() {
        return (this->tcp_hl >> 4) * 4;
    }
};

struct Pseudo_hdr {
    uint32_t sip;       
    uint32_t dip;       
    uint8_t  reserved = 0;  
    uint8_t  protocol = 6;  // TCP -> 6
    uint16_t tcp_len;   
};
#pragma pack(pop)

#define IPVERSION 4

#endif