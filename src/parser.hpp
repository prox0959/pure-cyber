#pragma once
#include <string>
#include <vector>
#include <cstdint>

// ============================================================
//  parser.hpp — HTTP ve DNS paket ayrıştırma
// ============================================================

// Ethernet frame boyutları
#define ETHER_HDR_LEN   14
#define IP_HDR_MIN_LEN  20
#define TCP_HDR_MIN_LEN 20
#define UDP_HDR_LEN     8

// Protokol numaraları
#define PROTO_TCP 6
#define PROTO_UDP 17

// Ethernet type
#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_ARP  0x0806

namespace Parser {

#pragma pack(push, 1)
    struct EthernetHeader {
        uint8_t  dst_mac[6];
        uint8_t  src_mac[6];
        uint16_t ether_type;  // network byte order
    };

    struct IPv4Header {
        uint8_t  ver_ihl;       // version (4 bit) + IHL (4 bit)
        uint8_t  dscp_ecn;
        uint16_t total_length;  // network byte order
        uint16_t identification;
        uint16_t flags_frag;
        uint8_t  ttl;
        uint8_t  protocol;
        uint16_t checksum;
        uint32_t src_ip;        // network byte order
        uint32_t dst_ip;        // network byte order
    };

    struct TCPHeader {
        uint16_t src_port;      // network byte order
        uint16_t dst_port;      // network byte order
        uint32_t seq_num;
        uint32_t ack_num;
        uint8_t  data_offset;   // header length in 32-bit words (upper 4 bits)
        uint8_t  flags;
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent;
    };

    struct UDPHeader {
        uint16_t src_port;      // network byte order
        uint16_t dst_port;      // network byte order
        uint16_t length;
        uint16_t checksum;
    };
#pragma pack(pop)

    // Ayrıştırılmış HTTP paket verisi
    struct HTTPPacket {
        std::string src_ip;
        std::string dst_ip;
        std::string src_mac;
        std::string vendor;
        std::string method;         // GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
        std::string host;           // Host: header değeri
        std::string path;           // URL path
        std::string user_agent;     // User-Agent header
        std::string os_guess;       // UA'dan tahmin edilen OS
        std::string browser;        // UA'dan çıkan tarayıcı
        std::string content_type;   // Content-Type header
        std::string referer;        // Referer header
        std::string cookies;        // Cookie header (kısaltılmış)
        std::string payload;        // İlk N byte (Config::MAX_PAYLOAD_DISPLAY)
        int src_port = 0;
        int dst_port = 0;
    };

    // Ayrıştırılmış DNS sorgusu
    struct DNSPacket {
        std::string src_ip;
        std::string src_mac;
        std::string vendor;
        std::vector<std::string> queries;  // Sorgulanan domain adları
    };

    // Ham paket verisinden HTTP paketi ayrıştır
    // Başarılıysa true döner, out doldurulur
    bool ParseHTTP(const uint8_t* data, int len, HTTPPacket& out);

    // Ham paket verisinden DNS sorgusu ayrıştır
    // Başarılıysa true döner, out doldurulur
    bool ParseDNS(const uint8_t* data, int len, DNSPacket& out);

    // TCP payload'ından HTTP methodunu kontrol et
    bool IsHTTPRequest(const uint8_t* payload, int payload_len);

    // HTTP header'larından belirli bir field'ı çıkar
    std::string ExtractHTTPHeader(const std::string& raw, const std::string& field_name);
}
