#include "parser.hpp"
#include "device_info.hpp"
#include "../config.hpp"
#include <winsock2.h>
#include <algorithm>
#include <sstream>
#include <string>
#include <cstring>

// ============================================================
//  parser.cpp — HTTP ve DNS paket ayrıştırma implementasyonu
// ============================================================

namespace Parser {

    // ─── Yardımcı: HTTP method kontrolü ─────────────────────────────────────
    static const char* HTTP_METHODS[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
    };

    bool IsHTTPRequest(const uint8_t* payload, int payload_len) {
        if (payload_len < 6) return false;
        for (auto& m : HTTP_METHODS) {
            size_t mlen = strlen(m);
            if (payload_len >= (int)mlen &&
                memcmp(payload, m, mlen) == 0)
            {
                return true;
            }
        }
        return false;
    }

    // ─── HTTP Header field çıkarma ────────────────────────────────────────────
    std::string ExtractHTTPHeader(const std::string& raw, const std::string& field_name) {
        // Büyük/küçük harf duyarsız arama için normalize et
        std::string raw_lower = raw;
        std::string field_lower = field_name + ":";
        std::transform(raw_lower.begin(), raw_lower.end(), raw_lower.begin(), ::tolower);
        std::transform(field_lower.begin(), field_lower.end(), field_lower.begin(), ::tolower);

        auto pos = raw_lower.find(field_lower);
        if (pos == std::string::npos) return "";

        // Field başlangıcından sonraki değeri al
        pos += field_lower.size();
        // Boşlukları atla
        while (pos < raw.size() && (raw[pos] == ' ' || raw[pos] == '\t')) ++pos;

        // Satır sonuna kadar oku
        auto end = raw.find("\r\n", pos);
        if (end == std::string::npos) end = raw.find('\n', pos);
        if (end == std::string::npos) end = raw.size();

        return raw.substr(pos, end - pos);
    }

    // ─── HTTP Paketi Ayrıştır ─────────────────────────────────────────────────
    bool ParseHTTP(const uint8_t* data, int len, HTTPPacket& out) {
        if (len < ETHER_HDR_LEN + IP_HDR_MIN_LEN + TCP_HDR_MIN_LEN) return false;

        // Ethernet Header
        const auto* eth = reinterpret_cast<const EthernetHeader*>(data);
        uint16_t ether_type = ntohs(eth->ether_type);
        if (ether_type != ETHERTYPE_IP) return false;

        // IPv4 Header
        const uint8_t* ip_start = data + ETHER_HDR_LEN;
        const auto* ip = reinterpret_cast<const IPv4Header*>(ip_start);
        if (ip->protocol != PROTO_TCP) return false;

        int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;
        if (ip_hdr_len < IP_HDR_MIN_LEN) return false;

        // TCP Header
        const uint8_t* tcp_start = ip_start + ip_hdr_len;
        const auto* tcp = reinterpret_cast<const TCPHeader*>(tcp_start);

        int tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < TCP_HDR_MIN_LEN) return false;

        // Payload
        const uint8_t* payload = tcp_start + tcp_hdr_len;
        int payload_len = len - (int)(payload - data);
        if (payload_len <= 0) return false;

        // HTTP request kontrolü
        if (!IsHTTPRequest(payload, payload_len)) return false;

        // Raw HTTP string'e çevir (sadece ASCII kısım, max 8KB)
        int read_len = std::min(payload_len, 8192);
        std::string raw_http(reinterpret_cast<const char*>(payload), read_len);

        // İlk satırdan method ve path çıkar
        auto first_line_end = raw_http.find("\r\n");
        if (first_line_end == std::string::npos) first_line_end = raw_http.find('\n');
        if (first_line_end == std::string::npos) return false;

        std::string first_line = raw_http.substr(0, first_line_end);
        // Format: METHOD /path HTTP/1.x
        auto space1 = first_line.find(' ');
        if (space1 == std::string::npos) return false;
        auto space2 = first_line.find(' ', space1 + 1);
        if (space2 == std::string::npos) return false;

        out.method = first_line.substr(0, space1);
        out.path   = first_line.substr(space1 + 1, space2 - space1 - 1);

        // HTTP Header'ları çıkar
        out.host         = ExtractHTTPHeader(raw_http, "Host");
        out.user_agent   = ExtractHTTPHeader(raw_http, "User-Agent");
        out.content_type = ExtractHTTPHeader(raw_http, "Content-Type");
        out.referer      = ExtractHTTPHeader(raw_http, "Referer");

        // Cookie'yi kısalt
        std::string cookie_raw = ExtractHTTPHeader(raw_http, "Cookie");
        if (!cookie_raw.empty()) {
            out.cookies = cookie_raw.substr(0, 100);
            if (cookie_raw.size() > 100) out.cookies += "...";
        }

        // OS ve browser fingerprint
        if (!out.user_agent.empty()) {
            out.os_guess = DeviceInfo::GuessOS(out.user_agent);
            out.browser  = DeviceInfo::ExtractBrowser(out.user_agent);
            // User-Agent'ı kısalt
            if (out.user_agent.size() > 120)
                out.user_agent = out.user_agent.substr(0, 120) + "...";
        }

        // Payload (Config ayarına göre)
        if (Config::SHOW_PAYLOAD) {
            // Header'dan sonraki body kısmını al
            auto body_start = raw_http.find("\r\n\r\n");
            if (body_start != std::string::npos) {
                body_start += 4;
                int body_len = std::min((int)(raw_http.size() - body_start),
                                        Config::MAX_PAYLOAD_DISPLAY);
                if (body_len > 0)
                    out.payload = raw_http.substr(body_start, body_len);
            }
        }

        // IP ve MAC bilgileri
        out.src_ip   = DeviceInfo::FormatIP(ip->src_ip);
        out.dst_ip   = DeviceInfo::FormatIP(ip->dst_ip);
        out.src_mac  = DeviceInfo::FormatMAC(eth->src_mac);
        out.vendor   = DeviceInfo::LookupVendor(eth->src_mac);
        out.src_port = ntohs(tcp->src_port);
        out.dst_port = ntohs(tcp->dst_port);

        return true;
    }

    // ─── DNS Label Decode ─────────────────────────────────────────────────────
    // DNS label-encoded domain name'i string'e çevir
    // Pointer (0xC0) desteği dahil
    static std::string DecodeDNSName(const uint8_t* dns_start, int dns_len,
                                      const uint8_t* ptr, int& consumed) {
        std::string result;
        bool first = true;
        int safety = 0;
        const uint8_t* cur = ptr;

        while (safety++ < 128) {
            if (cur >= dns_start + dns_len) break;

            uint8_t label_len = *cur;

            if (label_len == 0) {
                ++cur;
                break;
            }

            // Pointer (compression)
            if ((label_len & 0xC0) == 0xC0) {
                if (cur + 1 >= dns_start + dns_len) break;
                uint16_t offset = ((label_len & 0x3F) << 8) | *(cur + 1);
                cur += 2;
                // Pointer'ı takip et (consumed güncelleme yok, sadece ad devam eder)
                int dummy = 0;
                result += DecodeDNSName(dns_start, dns_len, dns_start + offset, dummy);
                consumed = (int)(cur - ptr);
                return result;
            }

            ++cur;
            if (!first) result += '.';
            first = false;

            for (int i = 0; i < label_len; ++i) {
                if (cur >= dns_start + dns_len) break;
                result += (char)*cur;
                ++cur;
            }
        }

        consumed = (int)(cur - ptr);
        return result;
    }

    // ─── DNS Paketi Ayrıştır ─────────────────────────────────────────────────
    bool ParseDNS(const uint8_t* data, int len, DNSPacket& out) {
        if (len < ETHER_HDR_LEN + IP_HDR_MIN_LEN + UDP_HDR_LEN + 12) return false;

        // Ethernet
        const auto* eth = reinterpret_cast<const EthernetHeader*>(data);
        uint16_t ether_type = ntohs(eth->ether_type);
        if (ether_type != ETHERTYPE_IP) return false;

        // IPv4
        const uint8_t* ip_start = data + ETHER_HDR_LEN;
        const auto* ip = reinterpret_cast<const IPv4Header*>(ip_start);
        if (ip->protocol != PROTO_UDP) return false;

        int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;

        // UDP
        const uint8_t* udp_start = ip_start + ip_hdr_len;
        const auto* udp = reinterpret_cast<const UDPHeader*>(udp_start);

        // Sadece DNS sorgularını al (src port != 53, dst port == 53)
        uint16_t dst_port = ntohs(udp->dst_port);
        uint16_t src_port = ntohs(udp->src_port);
        if (dst_port != 53 && src_port != 53) return false;
        // Sadece queries (QR bit == 0)
        if (src_port == 53) return false;  // Response, istemiyoruz

        // DNS payload
        const uint8_t* dns = udp_start + UDP_HDR_LEN;
        int dns_len = len - (int)(dns - data);
        if (dns_len < 12) return false;

        // DNS Header
        // uint16_t tx_id    = (dns[0] << 8) | dns[1];
        uint16_t flags    = (dns[2] << 8) | dns[3];
        uint16_t qdcount  = (dns[4] << 8) | dns[5];

        // QR bit: 0 = query, 1 = response
        if ((flags >> 15) & 1) return false;  // Response, skip

        // Question section: 12 byte header'dan sonra başlar
        const uint8_t* qptr = dns + 12;
        int remaining = dns_len - 12;

        for (int q = 0; q < qdcount && remaining > 0; ++q) {
            int consumed = 0;
            std::string domain = DecodeDNSName(dns, dns_len, qptr, consumed);

            if (!domain.empty()) {
                out.queries.push_back(domain);
            }

            qptr     += consumed;
            remaining -= consumed;

            // QTYPE (2) + QCLASS (2) = 4 byte atla
            if (remaining >= 4) {
                qptr     += 4;
                remaining -= 4;
            }
        }

        if (out.queries.empty()) return false;

        // IP ve MAC
        out.src_ip  = DeviceInfo::FormatIP(ip->src_ip);
        out.src_mac = DeviceInfo::FormatMAC(eth->src_mac);
        out.vendor  = DeviceInfo::LookupVendor(eth->src_mac);

        return true;
    }
}
