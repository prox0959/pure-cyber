#include "display.hpp"
#include "credential.hpp"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <vector>
#include <algorithm>

// ============================================================
//  display.cpp — Renkli terminal çıktısı implementasyonu
// ============================================================

namespace Display {

    void Init() {
        // Windows 10+ için ANSI escape kod desteğini etkinleştir
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);

        // UTF-8 çıktı
        SetConsoleOutputCP(CP_UTF8);
    }

    void PrintBanner() {
        std::cout << CYAN << BOLD;
        std::cout << R"(
  ██████╗ ██╗   ██╗██████╗ ███████╗     ██████╗██╗   ██╗██████╗ ███████╗██████╗ 
  ██╔══██╗██║   ██║██╔══██╗██╔════╝    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
  ██████╔╝██║   ██║██████╔╝█████╗      ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
  ██╔═══╝ ██║   ██║██╔══██╗██╔══╝      ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
  ██║     ╚██████╔╝██║  ██║███████╗    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
)" << RESET;

        std::cout << YELLOW << "  [ Pasif Ağ Trafik Analizörü | CGNAT / Shared-IP Monitor ]" << RESET << "\n";
        std::cout << GRAY  << "  [ HTTP • DNS • Device Fingerprinting • Webhook Support ]"  << RESET << "\n";
        std::cout << RED   << "  [ Yalnızca kendi ağında veya yetkili ortamlarda kullan! ]" << RESET << "\n\n";

        PrintSeparator();
    }

    std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        struct tm tmInfo;
        localtime_s(&tmInfo, &t);
        std::ostringstream ss;
        ss << std::setfill('0')
           << std::setw(2) << tmInfo.tm_hour << ":"
           << std::setw(2) << tmInfo.tm_min  << ":"
           << std::setw(2) << tmInfo.tm_sec;
        return ss.str();
    }

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
    ) {
        // Method rengi
        std::string method_color = GREEN;
        if (method == "POST")   method_color = YELLOW;
        if (method == "DELETE") method_color = RED;
        if (method == "PUT")    method_color = MAGENTA;

        std::cout << "\n";
        std::cout << GRAY << "[" << timestamp << "] " << RESET
                  << method_color << BOLD << "[HTTP " << method << "]" << RESET << "\n";

        std::cout << BLUE  << "  ├─ Kaynak  : " << RESET << src_ip << ":" << src_port;
        if (!src_mac.empty()) {
            std::cout << GRAY << "  (" << src_mac << ")" << RESET;
        }
        if (!vendor.empty()) {
            std::cout << CYAN << " [" << vendor << "]" << RESET;
        }
        std::cout << "\n";

        std::cout << BLUE  << "  ├─ Hedef   : " << RESET << dst_ip << ":" << dst_port << "\n";

        if (!host.empty()) {
            std::cout << GREEN << "  ├─ Host    : " << RESET << BOLD << host << RESET << path << "\n";
        }

        if (!user_agent.empty()) {
            std::cout << YELLOW << "  ├─ Browser : " << RESET << user_agent.substr(0, 80);
            if (user_agent.size() > 80) std::cout << "...";
            std::cout << "\n";
        }

        if (!os_guess.empty()) {
            std::cout << MAGENTA << "  ├─ OS Tahmini: " << RESET << os_guess << "\n";
        }

        if (!content_type.empty()) {
            std::cout << GRAY << "  └─ Content : " << RESET << content_type << "\n";
        }
    }

    void PrintDNS(
        const std::string& timestamp,
        const std::string& src_ip,
        const std::string& src_mac,
        const std::string& vendor,
        const std::string& queried_domain
    ) {
        std::cout << "\n";
        std::cout << GRAY << "[" << timestamp << "] " << RESET
                  << CYAN << BOLD << "[DNS]" << RESET << "\n";

        std::cout << BLUE << "  ├─ Kaynak  : " << RESET << src_ip;
        if (!src_mac.empty()) {
            std::cout << GRAY << " (" << src_mac << ")" << RESET;
        }
        if (!vendor.empty()) {
            std::cout << CYAN << " [" << vendor << "]" << RESET;
        }
        std::cout << "\n";

        std::cout << GREEN << "  └─ Domain  : " << RESET << BOLD << queried_domain << RESET << "\n";
    }

    void PrintInfo(const std::string& msg) {
        std::cout << CYAN << "[*] " << RESET << msg << "\n";
    }

    void PrintError(const std::string& msg) {
        std::cout << RED << "[!] HATA: " << RESET << msg << "\n";
    }

    void PrintInterface(int idx, const std::string& name, const std::string& desc, const std::string& ip) {
        std::cout << YELLOW << "  [" << idx << "] " << RESET
                  << BOLD << name << RESET;
        if (!desc.empty()) {
            std::cout << GRAY << " — " << desc << RESET;
        }
        if (!ip.empty()) {
            std::cout << GREEN << " (" << ip << ")" << RESET;
        }
        std::cout << "\n";
    }

    void PrintWebhookSent(bool success) {
        if (success) {
            std::cout << GREEN << GRAY << "  [webhook ✓]" << RESET << "\n";
        } else {
            std::cout << RED << GRAY << "  [webhook ✗]" << RESET << "\n";
        }
    }

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
    ) {
        std::cout << "\n";
        std::cout << GRAY << "[" << timestamp << "] " << RESET
                  << GREEN << BOLD << "[HTTPS 🔐]" << RESET
                  << GRAY << " (" << tls_version << ")" << RESET << "\n";

        std::cout << BLUE  << "  ├─ Kaynak  : " << RESET << src_ip << ":" << src_port;
        if (!src_mac.empty()) {
            std::cout << GRAY << "  (" << src_mac << ")" << RESET;
        }
        if (!vendor.empty()) {
            std::cout << CYAN << " [" << vendor << "]" << RESET;
        }
        std::cout << "\n";

        std::cout << BLUE  << "  ├─ Hedef   : " << RESET << dst_ip << ":" << dst_port << "\n";
        std::cout << GREEN << "  └─ SNI     : " << RESET << BOLD << "https://" << sni << RESET << "\n";
    }

    void PrintCredential(
        const std::string& timestamp,
        const Credential::CredEntry& cred
    ) {
        std::cout << "\n";
        std::cout << GRAY << "[" << timestamp << "] " << RESET;

        if (cred.has_sensitive) {
            std::cout << RED << BOLD << "[🔑 KREDENSİYEL TESPİT EDİLDİ!]" << RESET << "\n";
        } else {
            std::cout << YELLOW << BOLD << "[📋 POST FORM VERİSİ]" << RESET << "\n";
        }

        std::cout << BLUE << "  ├─ Kaynak  : " << RESET << cred.src_ip;
        if (!cred.src_mac.empty()) std::cout << GRAY << " (" << cred.src_mac << ")" << RESET;
        if (!cred.vendor.empty())  std::cout << CYAN << " [" << cred.vendor << "]" << RESET;
        std::cout << "\n";

        std::cout << BLUE << "  ├─ Hedef   : " << RESET << BOLD << cred.host << cred.path << RESET << "\n";
        std::cout << MAGENTA << "  └─ Alanlar :" << RESET << "\n";

        for (const auto& [k, v] : cred.fields) {
            bool sensitive = Credential::IsSensitiveField(k);
            if (sensitive) {
                std::cout << "       " << RED << BOLD << k << RESET
                          << RED << " = " << v << RESET << "\n";
            } else {
                std::cout << "       " << CYAN << k << RESET
                          << " = " << v << "\n";
            }
        }
    }

    void PrintSeparator() {
        std::cout << GRAY << "  " << std::string(75, '─') << RESET << "\n";
    }
}
