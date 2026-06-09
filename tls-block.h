#pragma once
#include <pcap.h>
#include "struct_hdr.h"

extern Mac my_mac;

uint16_t calc_checksum(uint16_t* data, int len);
bool get_mac(const char* dev, Mac* mac_addr);
void send_rst(const u_char* origin, pcap_t* handle);
void send_backward_rst(const u_char* origin);