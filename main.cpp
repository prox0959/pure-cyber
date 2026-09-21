#include "src/capture.hpp"
#include "src/display.hpp"
#include "src/webhook.hpp"
#include "config.hpp"

#include <windows.h>
#include <iostream>
#include <string>
#include <csignal>
#include <cstdlib>

// ============================================================
//  main.cpp — PureCyber Network Sniffer
//  Kullanım: purecyber.exe [interface_no] [--webhook URL]
//            purecyber.exe --list         → Interface listesi
//            purecyber.exe --help         → Yardım
// ============================================================

// Ctrl+C sinyalini yakala
static void SignalHandler(int /*sig*/) {
    std::cout << "\n";
    Display::PrintInfo("Durdurma sinyali alındı, kapatılıyor...");
    Capture::PrintStats();
    Capture::Stop();
    Webhook::Cleanup();
    std::exit(0);
}

static void PrintHelp(const char* prog_name) {
    std::cout << "\nKullanım:\n"
              << "  " << prog_name << "                   → Otomatik interface seç, yakala\n"
              << "  " << prog_name << " --list            → Mevcut arayüzleri listele\n"
              << "  " << prog_name << " 2                 → Interface #2'yi kullan\n"
              << "  " << prog_name << " --webhook <URL>   → Webhook URL'ini çalışma zamanında set et\n"
              << "  " << prog_name << " --payload         → HTTP body payload'ı da göster\n"
              << "  " << prog_name << " --no-dns          → DNS sorgularını atla\n"
              << "  " << prog_name << " --no-log          → Dosyaya yazma\n"
              << "  " << prog_name << " --silent          → Terminal çıktısını kapat (sadece webhook)\n"
              << "  " << prog_name << " --help            → Bu yardım\n\n"
              << "Örnek:\n"
              << "  " << prog_name << " --webhook https://discord.com/api/webhooks/xxx/yyy\n"
              << "  " << prog_name << " 3 --payload --no-dns\n\n";
}

int main(int argc, char* argv[]) {
    // Terminal başlat
    Display::Init();
    Display::PrintBanner();

    // ── Argümanları Parse Et ──────────────────────────────────────────────────
    int interface_idx = 0;  // 0 = otomatik

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);

        if (arg == "--help" || arg == "-h") {
            PrintHelp(argv[0]);
            return 0;
        }
        else if (arg == "--list" || arg == "-l") {
            Capture::ListInterfaces();
            return 0;
        }
        else if (arg == "--webhook" || arg == "-w") {
            if (i + 1 < argc) {
                Config::WEBHOOK_URL = argv[++i];
                Display::PrintInfo("Webhook ayarlandı: " + Config::WEBHOOK_URL.substr(0, 40) + "...");
            } else {
                Display::PrintError("--webhook parametresi URL gerektiriyor!");
                return 1;
            }
        }
        else if (arg == "--payload") {
            Config::SHOW_PAYLOAD = true;
            Display::PrintInfo("Payload gösterimi açıldı");
        }
        else if (arg == "--no-dns") {
            Config::CAPTURE_DNS = false;
            Display::PrintInfo("DNS yakalama devre dışı");
        }
        else if (arg == "--no-log") {
            Config::LOG_TO_FILE = false;
            Display::PrintInfo("Log dosyası devre dışı");
        }
        else if (arg == "--silent") {
            Config::TERMINAL_OUTPUT = false;
            Display::PrintInfo("Terminal çıktısı kapatıldı (sadece webhook modu)");
        }
        else if (arg == "--filter" || arg == "-f") {
            if (i + 1 < argc) {
                Config::BPF_FILTER = argv[++i];
                Display::PrintInfo("BPF filtresi: " + Config::BPF_FILTER);
            }
        }
        else {
            // Sayı mı? → Interface index
            try {
                interface_idx = std::stoi(arg);
                Display::PrintInfo("Seçilen interface: #" + arg);
            } catch (...) {
                Display::PrintError("Bilinmeyen parametre: " + arg);
                PrintHelp(argv[0]);
                return 1;
            }
        }
    }

    // ── Webhook bilgisi ───────────────────────────────────────────────────────
    if (Webhook::IsEnabled()) {
        Display::PrintInfo("Webhook aktif → " + Config::WEBHOOK_URL.substr(0, 50) + "...");
    } else {
        Display::PrintInfo("Webhook: KAPALI (ayarlamak için --webhook <URL> kullan)");
    }

    // ── Ctrl+C handler ────────────────────────────────────────────────────────
    signal(SIGINT,  SignalHandler);
    signal(SIGTERM, SignalHandler);

    // ── Webhook init ──────────────────────────────────────────────────────────
    Webhook::Init();

    // ── Yakalamayı başlat ─────────────────────────────────────────────────────
    // Yönetici hakları gerekli! Npcap driver-level çalışır.
    bool ok = Capture::Start(interface_idx);
    if (!ok) {
        Display::PrintError("Yakalama başlatılamadı.");
        Display::PrintInfo("Not: Yönetici olarak çalıştırdığından emin ol! (Run as Administrator)");
        Webhook::Cleanup();
        return 1;
    }

    Webhook::Cleanup();
    return 0;
}
