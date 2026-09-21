#pragma once
#include <string>
#include <unordered_map>
#include <cstdint>

// ============================================================
//  device_info.hpp — Cihaz bilgisi (MAC, vendor, OS fingerprint)
// ============================================================

namespace DeviceInfo {

    // MAC adresini okunabilir formata çevir (XX:XX:XX:XX:XX:XX)
    std::string FormatMAC(const uint8_t* mac_bytes);

    // MAC'ten OUI (ilk 3 oktet) çıkar ve üreticiyi bul
    std::string LookupVendor(const uint8_t* mac_bytes);

    // User-Agent string'inden işletim sistemi tahmin et
    std::string GuessOS(const std::string& user_agent);

    // User-Agent string'inden tarayıcı çıkar (kısaltılmış)
    std::string ExtractBrowser(const std::string& user_agent);

    // IP adresini string'e çevir (network byte order → dotted decimal)
    std::string FormatIP(uint32_t ip_net);

    // Kısa OUI → Vendor tablosu (yaygın üreticiler)
    // Key: "AA:BB:CC" (uppercase), Value: vendor adı
    const std::unordered_map<std::string, std::string>& GetVendorTable();
}
