#include "tls-parser.h"
#include "tls-block.h"
#include "struct_hdr.h"
#include <map>
#include <vector>

struct FlowKey {
    uint32_t sip, dip; 
    uint16_t sport, dport;
    bool operator<(const FlowKey& o) const {
        if(sip != o.sip) return sip < o.sip;
        if(sport != o.sport) return sport < o.sport;
        if(dip != o.dip) return dip < o.dip;
        return dport < o.dport;
    }
};

static std::map<FlowKey, std::vector<uint8_t>> flows;

bool process_tls_segment(const u_char* pkt, const u_char* payload, int len, std::string& sni) {
    Ipv4_hdr* ip = (Ipv4_hdr*)(pkt + sizeof(Eth_hdr));
    Tcp_hdr* tcp = (Tcp_hdr*)(pkt + sizeof(Eth_hdr) + ip->get_ihl());
    FlowKey key = {ip->sip, ip->dip, tcp->tcp_src, tcp->tcp_dst};
    
    std::vector<uint8_t>& buf = flows[key];
    buf.insert(buf.end(), payload, payload + len);

    if(buf.size() < 9 || buf[0] != 0x16 || buf[5] != 0x01) return false;

    uint16_t record_len = (buf[3] << 8) | buf[4];
    if(buf.size() < 5U + record_len) return false;

    const uint8_t* h = buf.data() + 9;
    size_t off = 34;

    if(off + 1 > record_len) return false;
    off += 1 + h[off];

    if(off + 2 > record_len) return false;
    off += 2 + ((h[off] << 8) | h[off+1]);

    if(off + 1 > record_len) return false;
    off += 1 + h[off];

    if(off + 2 > record_len) return false;
    uint16_t ext_len = (h[off] << 8) | h[off+1];
    off += 2;

    size_t e_off = 0;
    while(e_off + 4 <= ext_len) {
        uint16_t type = (h[off+e_off] << 8) | h[off+e_off+1];
        uint16_t elen = (h[off+e_off+2] << 8) | h[off+e_off+3];
        e_off += 4;
        
        if(type == 0x0000 && elen >= 2) {
            const uint8_t* sni_data = &h[off+e_off-4+4];
            size_t n_off = 2;
            
            while(n_off + 3 <= elen) {
                if(sni_data[n_off] == 0x00) {
                    uint16_t nlen = (sni_data[n_off+1] << 8) | sni_data[n_off+2];
                    sni.assign((const char*)&sni_data[n_off+3], nlen);
                    return true;
                }
                n_off += 3 + ((sni_data[n_off+1] << 8) | sni_data[n_off+2]);
            }
        }
        e_off += elen;
    }
    return false;
}