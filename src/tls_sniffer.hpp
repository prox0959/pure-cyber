#pragma once
#include <string>
#include <cstdint>

// ============================================================
//  tls_sniffer.hpp — TLS ClientHello SNI çıkarma
//
//  HTTPS trafiği şifreli olsa da TLS handshake'teki
//  Server Name Indication (SNI) extension PLAINTEXT gönderilir.
//  Bu sayede şifrelenmiş HTTPS bağlantılarında bile
//  hangi siteye bağlanıldığı görülebilir.
//
//  TLS Record → Handshake → ClientHello → Extensions → SNI
// ============================================================

namespace TLSSniffer {

    // Ayrıştırılmış TLS bağlantı verisi
    struct TLSPacket {
        std::string src_ip;
        std::string dst_ip;
        std::string src_mac;
        std::string vendor;
        std::string sni;        // Server Name (domain)
        std::string tls_version; // "TLS 1.2", "TLS 1.3" vb.
        int src_port = 0;
        int dst_port = 0;
    };

    // Ham Ethernet paketinden TLS ClientHello → SNI çıkar
    // Başarılıysa true döner, out doldurulur
    bool ParseSNI(const uint8_t* data, int len, TLSPacket& out);

    // TLS version byte'larından okunabilir string üret
    std::string FormatTLSVersion(uint8_t major, uint8_t minor);
}
