#include "tls_sniffer.hpp"
#include "parser.hpp"
#include "device_info.hpp"
#include <winsock2.h>
#include <cstring>
#include <string>

// ============================================================
//  tls_sniffer.cpp — TLS ClientHello SNI ayrıştırma
//
//  TLS Record yapısı:
//    [0]    Content Type: 0x16 = Handshake
//    [1-2]  Version: 0x0301 (TLS 1.0 compat) 
//    [3-4]  Length (2 bytes, big-endian)
//    [5]    Handshake Type: 0x01 = ClientHello
//    [6-8]  Length (3 bytes)
//    [9-10] Client Version
//    [11-42] Random (32 bytes)
//    [43]   Session ID Length
//    [44+]  Session ID
//    ...    Cipher Suites, Compression Methods
//    ...    Extensions
//              Extension Type 0x0000 = server_name
//              → SNI buradan okunur
// ============================================================

namespace TLSSniffer {

    std::string FormatTLSVersion(uint8_t major, uint8_t minor) {
        if (major == 3) {
            switch (minor) {
                case 1: return "TLS 1.0";
                case 2: return "TLS 1.1";
                case 3: return "TLS 1.2";
                case 4: return "TLS 1.3";
                default: return "TLS 3." + std::to_string(minor);
            }
        }
        if (major == 2) return "SSL 2.0";
        return "SSL/TLS unknown";
    }

    // ─── Ana ayrıştırma fonksiyonu ────────────────────────────────────────────
    bool ParseSNI(const uint8_t* data, int len, TLSPacket& out) {
        // Minimum: Ethernet(14) + IP(20) + TCP(20) + TLS record(5) + ClientHello min
        if (len < 14 + 20 + 20 + 5 + 40) return false;

        // ── Ethernet ──────────────────────────────────────────────────────────
        const auto* eth = reinterpret_cast<const Parser::EthernetHeader*>(data);
        if (ntohs(eth->ether_type) != 0x0800) return false;  // IPv4 değil

        // ── IPv4 ──────────────────────────────────────────────────────────────
        const uint8_t* ip_start = data + 14;
        const auto* ip = reinterpret_cast<const Parser::IPv4Header*>(ip_start);
        if (ip->protocol != 6) return false;  // TCP değil

        int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;

        // ── TCP ───────────────────────────────────────────────────────────────
        const uint8_t* tcp_start = ip_start + ip_hdr_len;
        const auto* tcp = reinterpret_cast<const Parser::TCPHeader*>(tcp_start);

        // Sadece HTTPS portlarına bağlantıları kontrol et
        uint16_t dst_port = ntohs(tcp->dst_port);
        if (dst_port != 443 && dst_port != 8443 && dst_port != 993 &&
            dst_port != 995 && dst_port != 465 && dst_port != 587) {
            return false;
        }

        int tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0F) * 4;

        // ── TLS Payload ───────────────────────────────────────────────────────
        const uint8_t* tls = tcp_start + tcp_hdr_len;
        int tls_len = len - (int)(tls - data);

        if (tls_len < 5) return false;

        // TLS Record Header
        uint8_t content_type = tls[0];
        if (content_type != 0x16) return false;  // Handshake değil

        // TLS version (record layer)
        uint8_t rec_major = tls[1];
        uint8_t rec_minor = tls[2];

        // Record length
        uint16_t record_len = (tls[3] << 8) | tls[4];
        if (tls_len < 5 + record_len) return false;

        // ── Handshake Layer ───────────────────────────────────────────────────
        const uint8_t* hs = tls + 5;
        int hs_len = record_len;

        if (hs_len < 4) return false;

        uint8_t hs_type = hs[0];
        if (hs_type != 0x01) return false;  // ClientHello değil

        // Handshake length (3 bytes big-endian)
        uint32_t hs_data_len = (hs[1] << 16) | (hs[2] << 8) | hs[3];
        const uint8_t* ch = hs + 4;  // ClientHello başlangıcı
        int ch_len = (int)hs_data_len;

        if (ch_len < 2 + 32 + 1) return false;

        // ── ClientHello Parse ─────────────────────────────────────────────────
        // Client Version (2 bytes)
        uint8_t ch_major = ch[0];
        uint8_t ch_minor = ch[1];
        (void)ch_major; (void)ch_minor;

        int pos = 2;

        // Random (32 bytes) — atla
        pos += 32;
        if (pos >= ch_len) return false;

        // Session ID
        uint8_t session_id_len = ch[pos++];
        pos += session_id_len;
        if (pos + 2 > ch_len) return false;

        // Cipher Suites Length
        uint16_t cs_len = (ch[pos] << 8) | ch[pos + 1];
        pos += 2 + cs_len;
        if (pos + 1 > ch_len) return false;

        // Compression Methods
        uint8_t comp_len = ch[pos++];
        pos += comp_len;
        if (pos + 2 > ch_len) return false;

        // Extensions Length
        uint16_t ext_total_len = (ch[pos] << 8) | ch[pos + 1];
        pos += 2;

        if (pos + ext_total_len > ch_len) return false;

        // ── Extensions: SNI (type 0x0000) arama ──────────────────────────────
        int ext_end = pos + ext_total_len;
        while (pos + 4 <= ext_end) {
            uint16_t ext_type = (ch[pos] << 8) | ch[pos + 1];
            uint16_t ext_len  = (ch[pos + 2] << 8) | ch[pos + 3];
            pos += 4;

            if (ext_type == 0x0000) {
                // server_name extension bulundu!
                // Format:
                //   [0-1] Server Name List Length
                //   [2]   Name Type: 0x00 = host_name
                //   [3-4] Name Length
                //   [5..] Name (ASCII domain)

                if (ext_len < 5) break;
                if (pos + ext_len > ext_end) break;

                // Server Name List Length (2 bytes)
                // uint16_t snl_len = (ch[pos] << 8) | ch[pos + 1];
                uint8_t name_type = ch[pos + 2];

                if (name_type != 0x00) break;  // host_name değil

                uint16_t name_len = (ch[pos + 3] << 8) | ch[pos + 4];
                if (pos + 5 + name_len > ext_end) break;

                // Domain adını çıkar
                out.sni = std::string(reinterpret_cast<const char*>(ch + pos + 5), name_len);

                // TLS versiyonunu belirle (ClientHello'daki version vs record version)
                // TLS 1.3 genellikle 0x0303 yazsa da extension ile negotiate edilir
                out.tls_version = FormatTLSVersion(rec_major, rec_minor);

                // IP ve MAC bilgileri
                out.src_ip   = DeviceInfo::FormatIP(ip->src_ip);
                out.dst_ip   = DeviceInfo::FormatIP(ip->dst_ip);
                out.src_mac  = DeviceInfo::FormatMAC(eth->src_mac);
                out.vendor   = DeviceInfo::LookupVendor(eth->src_mac);
                out.src_port = ntohs(tcp->src_port);
                out.dst_port = dst_port;

                return true;
            }

            pos += ext_len;
        }

        return false;  // SNI bulunamadı
    }
}
