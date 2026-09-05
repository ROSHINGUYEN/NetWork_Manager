#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packet_parser.h"

/* Hỗ trợ chuyển đổi Network Byte Order */
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

/* Tính checksum chuẩn RFC 1071 (cho IP, ICMP) */
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;
    return answer;
}

/* Format TCP Flags thành chuỗi string (Vd: "S.A.") */
void format_tcp_flags(uint8_t flags, char *out_str) {
    int i = 0;
    if (flags & TCP_SYN) out_str[i++] = 'S';
    if (flags & TCP_ACK) out_str[i++] = 'A';
    if (flags & TCP_FIN) out_str[i++] = 'F';
    if (flags & TCP_RST) out_str[i++] = 'R';
    if (flags & TCP_PSH) out_str[i++] = 'P';
    if (flags & TCP_URG) out_str[i++] = 'U';
    out_str[i] = '\0';
    if (i == 0) strcpy(out_str, "NONE");
}

/* Định dạng địa chỉ IP từ số */
void format_ip(const uint8_t *ip, char *out_str) {
    sprintf(out_str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

/* Định dạng địa chỉ MAC */
void format_mac(const uint8_t *mac, char *out_str) {
    sprintf(out_str, "%02X:%02X:%02X:%02X:%02X:%02X", 
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Hàm Export - Phân tích gói tin thô (L2 Ethernet frame) */
EXPORT_SYMBOL int parse_network_packet(const unsigned char *raw_data, int raw_len, struct ParsedPacket *out_pkt) {
    if (!raw_data || !out_pkt || raw_len < sizeof(struct eth_header)) {
        return -1; // Lỗi gói tin quá ngắn
    }

    // Khởi tạo struct đầu ra
    memset(out_pkt, 0, sizeof(struct ParsedPacket));
    out_pkt->packet_len = raw_len;
    out_pkt->threat.has_threat = 0;
    strcpy(out_pkt->protocol, "UNKNOWN");

    const struct eth_header *eth = (const struct eth_header *)raw_data;
    uint16_t ethertype = ntohs(eth->ethertype);
    int offset = sizeof(struct eth_header);

    if (ethertype == 0x0806) {
        // ARP Packet
        if (raw_len < offset + sizeof(struct arp_header)) return -1;
        const struct arp_header *arp = (const struct arp_header *)(raw_data + offset);
        
        strcpy(out_pkt->protocol, "ARP");
        format_ip(arp->sender_ip, out_pkt->src_ip);
        format_ip(arp->target_ip, out_pkt->dst_ip);
        
        uint16_t opcode = ntohs(arp->opcode);
        if (opcode == 1) {
            sprintf(out_pkt->info, "ARP Request: Who has %s? Tell %s", out_pkt->dst_ip, out_pkt->src_ip);
        } else if (opcode == 2) {
            sprintf(out_pkt->info, "ARP Reply: %s is at %02X:%02X:%02X:%02X:%02X:%02X", 
                    out_pkt->src_ip, arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2], 
                    arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
        }
        return 0;
    }
    
    if (ethertype != 0x0800) {
        // Không phải IPv4 (có thể là IPv6 0x86DD)
        return 0; 
    }

    // IPv4 Packet
    if (raw_len < offset + sizeof(struct ip_header)) return -1;
    const struct ip_header *ip = (const struct ip_header *)(raw_data + offset);
    
    format_ip(ip->src_ip, out_pkt->src_ip);
    format_ip(ip->dst_ip, out_pkt->dst_ip);
    
    int ip_header_len = ip->ihl * 4;
    if (ip_header_len < 20 || offset + ip_header_len > raw_len) return -1;
    
    // Kiểm tra IP Length Anomaly
    if (ntohs(ip->total_length) > raw_len - offset) {
        out_pkt->threat.has_threat = 1;
        out_pkt->threat.severity = 2; // Warning
        strcpy(out_pkt->threat.threat_type, "MALFORMED_IP");
        strcpy(out_pkt->threat.description, "Chiều dài gói IP (Total Length) vượt quá khung dữ liệu Ethernet.");
    }

    offset += ip_header_len;

    // L4 Phân tích (TCP, UDP, ICMP)
    if (ip->protocol == 6) {
        // TCP
        if (raw_len < offset + sizeof(struct tcp_header)) return -1;
        const struct tcp_header *tcp = (const struct tcp_header *)(raw_data + offset);
        
        strcpy(out_pkt->protocol, "TCP");
        out_pkt->src_port = ntohs(tcp->src_port);
        out_pkt->dst_port = ntohs(tcp->dst_port);
        format_tcp_flags(tcp->flags, out_pkt->tcp_flags_str);
        
        sprintf(out_pkt->info, "TCP %s: %d -> %d Seq=%u", out_pkt->tcp_flags_str, out_pkt->src_port, out_pkt->dst_port, ntohl(tcp->seq_num));

        // Security Heuristics cho TCP
        if (tcp->flags == TCP_SYN) {
            // Có thể là mở kết nối bình thường, nhưng SecurityEngine (Python) sẽ đánh giá tần suất (SYN Scan)
        } else if (tcp->flags == 0x00) {
            out_pkt->threat.has_threat = 1;
            out_pkt->threat.severity = 3; // Critical
            strcpy(out_pkt->threat.threat_type, "TCP_NULL_SCAN");
            strcpy(out_pkt->threat.description, "Gói tin TCP không có cờ nào được bật (NULL Scan) dùng để thăm dò Firewall.");
        } else if (tcp->flags == (TCP_FIN | TCP_PSH | TCP_URG)) {
            out_pkt->threat.has_threat = 1;
            out_pkt->threat.severity = 3; // Critical
            strcpy(out_pkt->threat.threat_type, "TCP_XMAS_SCAN");
            strcpy(out_pkt->threat.description, "Gói tin mang cờ FIN, PSH, URG (XMAS Scan) thám thính cổng.");
        } else if ((tcp->flags & TCP_SYN) && (tcp->flags & TCP_FIN)) {
            out_pkt->threat.has_threat = 1;
            out_pkt->threat.severity = 3; // Critical
            strcpy(out_pkt->threat.threat_type, "TCP_SYN_FIN_SCAN");
            strcpy(out_pkt->threat.description, "Gói tin có cả SYN và FIN - bất thường cấu trúc.");
        }

    } else if (ip->protocol == 17) {
        // UDP
        if (raw_len < offset + sizeof(struct udp_header)) return -1;
        const struct udp_header *udp = (const struct udp_header *)(raw_data + offset);
        
        strcpy(out_pkt->protocol, "UDP");
        out_pkt->src_port = ntohs(udp->src_port);
        out_pkt->dst_port = ntohs(udp->dst_port);
        
        sprintf(out_pkt->info, "UDP: %d -> %d Len=%d", out_pkt->src_port, out_pkt->dst_port, ntohs(udp->length));

    } else if (ip->protocol == 1) {
        // ICMP
        if (raw_len < offset + sizeof(struct icmp_header)) return -1;
        const struct icmp_header *icmp = (const struct icmp_header *)(raw_data + offset);
        
        strcpy(out_pkt->protocol, "ICMP");
        if (icmp->type == 8) {
            sprintf(out_pkt->info, "ICMP Echo Request (Ping) Seq=%d", ntohs(icmp->seq));
        } else if (icmp->type == 0) {
            sprintf(out_pkt->info, "ICMP Echo Reply Seq=%d", ntohs(icmp->seq));
        } else {
            sprintf(out_pkt->info, "ICMP Type=%d Code=%d", icmp->type, icmp->code);
        }
    }

    return 0; // Thành công
}
