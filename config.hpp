#pragma once
#include <string>

// ============================================================
//  PureCyber - Network Traffic Sniffer
//  config.hpp  — Genel ayarlar, buradan her şeyi özelleştir
// ============================================================

namespace Config {

    // Webhook URL'ini buraya yapıştır (Discord veya özel endpoint)
    // Boş bırakırsan webhook devre dışı kalır
    inline std::string WEBHOOK_URL = "";

    // Webhook gönderim aralığı (saniye) — throttle için
    inline int WEBHOOK_COOLDOWN_SEC = 2;

    // Ağ arayüzü seçimi (0 = otomatik, en iyi olanı seçer)
    inline int INTERFACE_INDEX = 0;

    // Promiscuous mode: ağdaki TÜM paketleri yakala (router seviyesinde çalışır)
    inline bool PROMISCUOUS = true;

    // Yakalamak istediğin portlar (BPF filtresi)
    // HTTP: 80, HTTPS: 443, Alt HTTP: 8080, DNS: 53
    inline std::string BPF_FILTER = "tcp port 80 or tcp port 8080 or udp port 53 or tcp port 443 or tcp port 8443";

    // Terminal çıktısı — false yaparak sadece webhook moduna alabilirsin
    inline bool TERMINAL_OUTPUT = true;

    // Yakalanan verileri dosyaya kaydet
    inline bool LOG_TO_FILE = true;
    inline std::string LOG_FILE = "capture.log";

    // MAC → Vendor veritabanı (kısaltılmış, yaygın üreticiler)
    // İlk 3 octet (OUI) bazlı
    inline bool VENDOR_LOOKUP = true;

    // OS fingerprint için User-Agent parse et
    inline bool UA_PARSE = true;

    // DNS sorgularını yakala ve göster
    inline bool CAPTURE_DNS = true;

    // HTTP payload (body) göster — büyük çıktı verebilir
    inline bool SHOW_PAYLOAD = false;

    // Maksimum payload gösterim uzunluğu (byte)
    inline int MAX_PAYLOAD_DISPLAY = 256;
}
