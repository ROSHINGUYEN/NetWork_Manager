#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>

/* Định nghĩa các thông số giới hạn */
#define MAX_IP_LEN 16
#define MAX_INFO_LEN 256
#define MAX_THREAT_DESC 128

/* Cấu trúc Header Mạng theo RFC (Network Byte Order) */
#pragma pack(push, 1)

// Ethernet II Header
struct eth_header {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
};

// ARP Header (IPv4 over Ethernet)
struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
};

// IPv4 Header
struct ip_header {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint8_t ihl:4;
    uint8_t version:4;
#else
    uint8_t version:4;
    uint8_t ihl:4;
#endif
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
};

// TCP Header
struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint8_t reserved1:4;
    uint8_t data_offset:4;
#else
    uint8_t data_offset:4;
    uint8_t reserved1:4;
#endif
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

// TCP Flags Macros
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

// UDP Header
struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

// ICMP Header
struct icmp_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

#pragma pack(pop)

/* Cấu trúc Dữ liệu Phân tích truyền về Python */
struct SecurityThreat {
    int      has_threat;          // 0: Không, 1: Có
    int      severity;            // 1: Info, 2: Warning, 3: Critical
    char     threat_type[32];     // VD: "TCP_SYN_SCAN", "ARP_SPOOF"
    char     description[MAX_THREAT_DESC];
};

struct ParsedPacket {
    char     protocol[16];        // TCP, UDP, ICMP, ARP...
    char     src_ip[MAX_IP_LEN];
    char     dst_ip[MAX_IP_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t packet_len;
    char     tcp_flags_str[16];   // "S..", ".A.", "F.P"
    char     info[MAX_INFO_LEN];  // Tóm tắt gói tin
    struct SecurityThreat threat; // Đánh giá an ninh
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
    #define EXPORT_SYMBOL __declspec(dllexport)
#else
    #define EXPORT_SYMBOL
#endif

// Hàm xuất khẩu cho Ctypes
EXPORT_SYMBOL int parse_network_packet(const unsigned char *raw_data, int raw_len, struct ParsedPacket *out_pkt);

#ifdef __cplusplus
}
#endif

#endif // PACKET_PARSER_H
