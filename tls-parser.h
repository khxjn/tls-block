#pragma once
#include <string>
#include <pcap.h>

bool process_tls_segment(const u_char* packet, const u_char* payload, int len, std::string& sni);