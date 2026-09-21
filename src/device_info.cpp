#include "device_info.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>

// ============================================================
//  device_info.cpp — Cihaz bilgisi implementasyonu
// ============================================================

namespace DeviceInfo {

    // ─── OUI Vendor Tablosu (en yaygın 150+ üretici) ────────────────────────
    const std::unordered_map<std::string, std::string>& GetVendorTable() {
        static const std::unordered_map<std::string, std::string> table = {
            // Apple
            {"00:03:93", "Apple"}, {"00:0A:27", "Apple"}, {"00:0A:95", "Apple"},
            {"00:11:24", "Apple"}, {"00:14:51", "Apple"}, {"00:16:CB", "Apple"},
            {"00:17:F2", "Apple"}, {"00:19:E3", "Apple"}, {"00:1B:63", "Apple"},
            {"00:1C:B3", "Apple"}, {"00:1D:4F", "Apple"}, {"00:1E:52", "Apple"},
            {"00:1F:5B", "Apple"}, {"00:1F:F3", "Apple"}, {"00:21:E9", "Apple"},
            {"00:22:41", "Apple"}, {"00:23:12", "Apple"}, {"00:23:32", "Apple"},
            {"00:23:6C", "Apple"}, {"00:24:36", "Apple"}, {"00:25:00", "Apple"},
            {"00:25:4B", "Apple"}, {"00:25:BC", "Apple"}, {"00:26:08", "Apple"},
            {"00:26:4A", "Apple"}, {"00:26:B0", "Apple"}, {"00:26:BB", "Apple"},
            {"00:3E:E1", "Apple"}, {"04:0C:CE", "Apple"}, {"04:15:52", "Apple"},
            {"04:26:65", "Apple"}, {"04:48:9A", "Apple"}, {"04:54:53", "Apple"},
            {"04:D3:CF", "Apple"}, {"04:F1:3E", "Apple"}, {"04:F7:E4", "Apple"},
            {"08:00:07", "Apple"}, {"08:6D:41", "Apple"}, {"0C:3E:9F", "Apple"},
            {"0C:74:C2", "Apple"}, {"10:40:F3", "Apple"}, {"10:9A:DD", "Apple"},
            {"14:10:9F", "Apple"}, {"18:AF:61", "Apple"}, {"18:E7:F4", "Apple"},
            {"1C:36:BB", "Apple"}, {"1C:AB:A7", "Apple"}, {"20:A2:E4", "Apple"},
            {"24:A0:74", "Apple"}, {"28:6A:BA", "Apple"}, {"28:E0:2C", "Apple"},
            {"2C:1F:23", "Apple"}, {"2C:61:F6", "Apple"}, {"30:10:B3", "Apple"},
            {"34:12:98", "Apple"}, {"34:36:3B", "Apple"}, {"34:C0:59", "Apple"},
            {"38:0F:4A", "Apple"}, {"3C:15:C2", "Apple"}, {"3C:D0:F8", "Apple"},
            {"40:83:1D", "Apple"}, {"40:A6:D9", "Apple"}, {"44:00:10", "Apple"},
            {"44:2A:60", "Apple"}, {"44:4C:0C", "Apple"}, {"44:FB:42", "Apple"},
            {"48:43:7C", "Apple"}, {"48:60:BC", "Apple"}, {"48:D7:05", "Apple"},
            {"4C:8D:79", "Apple"}, {"50:EA:D6", "Apple"}, {"54:26:96", "Apple"},
            {"54:AE:27", "Apple"}, {"58:55:CA", "Apple"}, {"5C:95:AE", "Apple"},
            {"5C:F9:38", "Apple"}, {"60:03:08", "Apple"}, {"60:33:4B", "Apple"},
            {"60:92:17", "Apple"}, {"60:A3:7D", "Apple"}, {"60:C5:47", "Apple"},
            {"60:D9:C7", "Apple"}, {"60:F4:45", "Apple"}, {"60:FA:CD", "Apple"},
            {"60:FB:42", "Apple"}, {"64:20:0C", "Apple"}, {"64:76:BA", "Apple"},
            {"64:A5:C3", "Apple"}, {"68:09:27", "Apple"}, {"68:5B:35", "Apple"},
            {"6C:3E:6D", "Apple"}, {"6C:40:08", "Apple"}, {"6C:70:9F", "Apple"},
            {"6C:72:E7", "Apple"}, {"6C:8D:C1", "Apple"}, {"70:14:A6", "Apple"},
            {"70:3E:AC", "Apple"}, {"70:56:81", "Apple"}, {"70:CD:60", "Apple"},
            {"70:DE:E2", "Apple"}, {"74:E1:B6", "Apple"}, {"78:31:C1", "Apple"},
            {"78:6C:1C", "Apple"}, {"78:7B:8A", "Apple"}, {"78:A3:E4", "Apple"},
            {"7C:11:BE", "Apple"}, {"7C:6D:62", "Apple"}, {"7C:C5:37", "Apple"},
            {"7C:D1:C3", "Apple"}, {"80:00:6E", "Apple"}, {"80:49:71", "Apple"},
            {"80:82:23", "Apple"}, {"80:BE:05", "Apple"}, {"80:EA:96", "Apple"},
            {"84:29:99", "Apple"}, {"84:38:35", "Apple"}, {"84:78:8B", "Apple"},
            {"84:8E:0C", "Apple"}, {"84:A1:34", "Apple"}, {"84:FC:AC", "Apple"},
            // Samsung
            {"00:07:AB", "Samsung"}, {"00:12:47", "Samsung"}, {"00:12:FB", "Samsung"},
            {"00:15:99", "Samsung"}, {"00:15:B9", "Samsung"}, {"00:16:32", "Samsung"},
            {"00:16:6B", "Samsung"}, {"00:16:6C", "Samsung"}, {"00:16:DB", "Samsung"},
            {"00:17:C9", "Samsung"}, {"00:17:D5", "Samsung"}, {"00:18:AF", "Samsung"},
            {"00:1A:8A", "Samsung"}, {"00:1B:98", "Samsung"}, {"00:1C:43", "Samsung"},
            {"00:1D:25", "Samsung"}, {"00:1D:F6", "Samsung"}, {"00:1E:7D", "Samsung"},
            {"00:1F:CC", "Samsung"}, {"00:21:19", "Samsung"}, {"00:21:D1", "Samsung"},
            {"00:21:D2", "Samsung"}, {"00:23:39", "Samsung"}, {"00:23:99", "Samsung"},
            {"00:24:54", "Samsung"}, {"00:24:90", "Samsung"}, {"00:24:91", "Samsung"},
            {"00:24:E9", "Samsung"}, {"00:25:38", "Samsung"}, {"00:25:66", "Samsung"},
            {"00:25:67", "Samsung"}, {"00:26:37", "Samsung"}, {"00:26:5F", "Samsung"},
            {"00:E3:B2", "Samsung"}, {"04:18:D6", "Samsung"}, {"04:FE:31", "Samsung"},
            {"08:08:C2", "Samsung"}, {"08:37:3D", "Samsung"}, {"08:D4:2B", "Samsung"},
            {"08:FC:88", "Samsung"}, {"0C:14:20", "Samsung"}, {"0C:71:5D", "Samsung"},
            {"10:1D:C0", "Samsung"}, {"10:30:47", "Samsung"}, {"14:49:E0", "Samsung"},
            {"14:89:FD", "Samsung"}, {"14:F4:2A", "Samsung"}, {"18:22:7E", "Samsung"},
            {"18:3A:2D", "Samsung"}, {"18:67:B0", "Samsung"}, {"1C:5A:6B", "Samsung"},
            {"1C:62:B8", "Samsung"}, {"1C:66:AA", "Samsung"}, {"1C:AF:05", "Samsung"},
            {"20:13:E0", "Samsung"}, {"20:64:32", "Samsung"}, {"20:6E:9C", "Samsung"},
            {"24:4B:03", "Samsung"}, {"24:C6:96", "Samsung"}, {"28:27:BF", "Samsung"},
            // Huawei
            {"00:00:FC", "Huawei"}, {"00:18:82", "Huawei"}, {"00:1E:10", "Huawei"},
            {"00:25:9E", "Huawei"}, {"00:34:FE", "Huawei"}, {"04:02:1F", "Huawei"},
            {"04:25:C5", "Huawei"}, {"04:BD:70", "Huawei"}, {"04:C0:6F", "Huawei"},
            {"04:F9:38", "Huawei"}, {"08:00:27", "Huawei"}, {"0C:37:DC", "Huawei"},
            {"0C:96:E6", "Huawei"}, {"10:1B:54", "Huawei"}, {"10:47:80", "Huawei"},
            {"10:C6:1F", "Huawei"}, {"14:B9:68", "Huawei"}, {"18:C5:8A", "Huawei"},
            {"1C:8E:5C", "Huawei"}, {"20:08:ED", "Huawei"}, {"20:2B:C1", "Huawei"},
            {"20:F3:A3", "Huawei"}, {"24:09:95", "Huawei"}, {"24:7F:3C", "Huawei"},
            {"28:31:52", "Huawei"}, {"28:3C:E4", "Huawei"}, {"28:6E:D4", "Huawei"},
            {"2C:AB:00", "Huawei"}, {"30:45:96", "Huawei"}, {"30:87:30", "Huawei"},
            {"34:6B:D3", "Huawei"}, {"34:B3:54", "Huawei"}, {"38:F8:89", "Huawei"},
            {"3C:47:11", "Huawei"}, {"3C:F8:08", "Huawei"}, {"40:4D:8E", "Huawei"},
            {"40:CB:A8", "Huawei"}, {"44:A1:91", "Huawei"}, {"48:00:31", "Huawei"},
            {"48:46:FB", "Huawei"}, {"48:AD:08", "Huawei"}, {"48:DB:50", "Huawei"},
            {"4C:1F:CC", "Huawei"}, {"4C:54:99", "Huawei"}, {"54:25:EA", "Huawei"},
            {"54:51:1B", "Huawei"}, {"54:89:98", "Huawei"}, {"58:2A:F7", "Huawei"},
            {"5C:C3:07", "Huawei"}, {"5C:FF:35", "Huawei"}, {"60:DE:44", "Huawei"},
            {"60:E7:01", "Huawei"}, {"64:16:F0", "Huawei"}, {"68:26:08", "Huawei"},
            {"68:CC:6E", "Huawei"}, {"6C:8D:C1", "Huawei"}, {"70:72:3C", "Huawei"},
            {"70:7B:E8", "Huawei"}, {"74:A0:2F", "Huawei"}, {"78:1D:BA", "Huawei"},
            {"7C:A2:3E", "Huawei"}, {"80:38:BC", "Huawei"}, {"80:FB:06", "Huawei"},
            // Xiaomi
            {"00:EC:0A", "Xiaomi"}, {"04:CF:8C", "Xiaomi"}, {"08:21:EF", "Xiaomi"},
            {"0C:1D:AF", "Xiaomi"}, {"10:2A:B3", "Xiaomi"}, {"10:6F:3F", "Xiaomi"},
            {"14:F6:5A", "Xiaomi"}, {"18:59:36", "Xiaomi"}, {"20:82:C0", "Xiaomi"},
            {"28:6C:07", "Xiaomi"}, {"34:80:B3", "Xiaomi"}, {"3C:BD:D8", "Xiaomi"},
            {"40:31:3C", "Xiaomi"}, {"50:EC:50", "Xiaomi"}, {"58:44:98", "Xiaomi"},
            {"64:09:80", "Xiaomi"}, {"64:CC:2E", "Xiaomi"}, {"68:DF:DD", "Xiaomi"},
            {"74:23:44", "Xiaomi"}, {"78:02:F8", "Xiaomi"}, {"7C:49:EB", "Xiaomi"},
            {"8C:BE:BE", "Xiaomi"}, {"98:FA:E3", "Xiaomi"}, {"9C:99:A0", "Xiaomi"},
            {"A0:86:C6", "Xiaomi"}, {"AC:C1:EE", "Xiaomi"}, {"B0:E2:35", "Xiaomi"},
            {"C4:0B:CB", "Xiaomi"}, {"D4:97:0B", "Xiaomi"}, {"F0:B4:29", "Xiaomi"},
            // Intel (genellikle laptop/PC wifi kartı)
            {"00:02:B3", "Intel"}, {"00:03:47", "Intel"}, {"00:04:23", "Intel"},
            {"00:0C:E5", "Intel"}, {"00:0E:0C", "Intel"}, {"00:0E:35", "Intel"},
            {"00:11:11", "Intel"}, {"00:12:F0", "Intel"}, {"00:13:02", "Intel"},
            {"00:13:20", "Intel"}, {"00:13:CE", "Intel"}, {"00:13:E8", "Intel"},
            {"00:15:00", "Intel"}, {"00:16:EA", "Intel"}, {"00:16:EB", "Intel"},
            {"00:16:76", "Intel"}, {"00:18:DE", "Intel"}, {"00:19:D2", "Intel"},
            {"00:1B:21", "Intel"}, {"00:1C:BF", "Intel"}, {"00:1D:E0", "Intel"},
            {"00:1E:64", "Intel"}, {"00:1E:65", "Intel"}, {"00:1F:3B", "Intel"},
            {"00:1F:3C", "Intel"}, {"00:21:5C", "Intel"}, {"00:21:5D", "Intel"},
            {"00:21:6A", "Intel"}, {"00:22:FA", "Intel"}, {"00:22:FB", "Intel"},
            {"00:23:14", "Intel"}, {"00:23:15", "Intel"}, {"00:24:D6", "Intel"},
            {"00:24:D7", "Intel"}, {"00:25:D3", "Intel"}, {"00:26:C6", "Intel"},
            {"00:26:C7", "Intel"}, {"00:27:10", "Intel"}, {"00:27:11", "Intel"},
            // Realtek (PC/laptop ethernet)
            {"00:01:6C", "Realtek"}, {"00:E0:4C", "Realtek"}, {"00:E0:EF", "Realtek"},
            {"52:54:00", "Realtek/QEMU"}, {"D8:CB:8A", "Realtek"},
            // TP-Link (router/modem)
            {"00:27:19", "TP-Link"}, {"08:95:2A", "TP-Link"}, {"10:FE:ED", "TP-Link"},
            {"14:CF:92", "TP-Link"}, {"18:A6:F7", "TP-Link"}, {"1C:61:B4", "TP-Link"},
            {"20:DC:E6", "TP-Link"}, {"24:69:A5", "TP-Link"}, {"28:87:BA", "TP-Link"},
            {"2C:D0:5A", "TP-Link"}, {"30:B5:C2", "TP-Link"}, {"34:60:F9", "TP-Link"},
            {"38:83:45", "TP-Link"}, {"3C:46:D8", "TP-Link"}, {"40:16:9F", "TP-Link"},
            {"44:94:FC", "TP-Link"}, {"48:8D:36", "TP-Link"}, {"4C:09:D4", "TP-Link"},
            {"50:C7:BF", "TP-Link"}, {"54:E6:FC", "TP-Link"}, {"58:D5:6E", "TP-Link"},
            {"5C:89:9A", "TP-Link"}, {"60:32:B1", "TP-Link"}, {"64:70:02", "TP-Link"},
            {"6C:19:8F", "TP-Link"}, {"70:4F:57", "TP-Link"}, {"74:DA:38", "TP-Link"},
            {"78:32:1B", "TP-Link"}, {"7C:8B:CA", "TP-Link"}, {"80:8F:1D", "TP-Link"},
            {"84:16:F9", "TP-Link"}, {"88:25:93", "TP-Link"}, {"8C:21:0A", "TP-Link"},
            {"90:5C:44", "TP-Link"}, {"94:0C:6D", "TP-Link"}, {"98:DA:C4", "TP-Link"},
            {"9C:A6:15", "TP-Link"}, {"A0:40:A0", "TP-Link"}, {"A4:2B:B0", "TP-Link"},
            {"A8:9F:BA", "TP-Link"}, {"AC:84:C9", "TP-Link"}, {"B0:48:7A", "TP-Link"},
            {"B0:95:75", "TP-Link"}, {"B4:B0:24", "TP-Link"}, {"B8:A3:86", "TP-Link"},
            {"BC:46:99", "TP-Link"}, {"C0:4A:00", "TP-Link"}, {"C4:6E:1F", "TP-Link"},
            {"C8:BE:19", "TP-Link"}, {"CC:32:E5", "TP-Link"}, {"D4:6E:0E", "TP-Link"},
            {"D8:07:B6", "TP-Link"}, {"DC:FE:18", "TP-Link"}, {"E0:28:6D", "TP-Link"},
            {"E4:20:C0", "TP-Link"}, {"E8:DE:27", "TP-Link"}, {"EC:08:6B", "TP-Link"},
            {"F0:C7:25", "TP-Link"}, {"F4:28:53", "TP-Link"}, {"F8:1A:67", "TP-Link"},
            {"FC:D7:33", "TP-Link"},
            // Türk Telekom / TTNet ekipmanları
            {"00:11:92", "TTNet/Technicolor"}, {"00:26:2D", "TTNet/Arcadyan"},
            {"00:90:D0", "TTNet/Alcatel"}, {"10:65:30", "TTNet/ZTE"},
            {"28:C6:8E", "TTNet/Technicolor"}, {"3C:A3:08", "TTNet/HuaweiMODEM"},
            {"54:10:EC", "TTNet/TechnicolorMODEM"}, {"80:1F:02", "TTNet/ZTE"},
            {"B8:62:1F", "TTNet/Technicolor"},
            // Google
            {"00:1A:11", "Google"}, {"08:9E:08", "Google"}, {"1C:F2:9A", "Google"},
            {"20:DF:B9", "Google"}, {"3C:5A:B4", "Google"}, {"48:D6:D5", "Google"},
            {"54:60:09", "Google"}, {"6C:AD:F8", "Google"}, {"70:3A:CB", "Google"},
            {"A4:77:33", "Google"}, {"AC:67:84", "Google"}, {"B0:E0:3C", "Google"},
            {"D0:E7:82", "Google"}, {"DC:A6:32", "Google (Nest)"},
            // Amazon
            {"00:BB:3A", "Amazon"}, {"0C:47:C9", "Amazon"}, {"18:74:2E", "Amazon"},
            {"28:37:37", "Amazon"}, {"30:8C:FB", "Amazon"}, {"34:D2:70", "Amazon"},
            {"38:F7:3D", "Amazon"}, {"40:B4:CD", "Amazon"}, {"44:65:0D", "Amazon"},
            {"44:EC:11", "Amazon"}, {"48:DF:F5", "Amazon"}, {"4C:EF:C0", "Amazon"},
            {"50:DC:E7", "Amazon"}, {"54:4B:8C", "Amazon"}, {"6C:56:97", "Amazon"},
            {"74:C2:46", "Amazon"}, {"84:D6:D0", "Amazon"}, {"8C:13:92", "Amazon"},
            {"A0:02:DC", "Amazon"}, {"B4:7C:9C", "Amazon"}, {"E4:B2:FB", "Amazon"},
            {"F0:27:65", "Amazon"}, {"FC:A1:83", "Amazon"},
            // Microsoft
            {"00:0D:3A", "Microsoft"}, {"00:12:5A", "Microsoft"}, {"00:15:5D", "Microsoft"},
            {"00:17:FA", "Microsoft"}, {"00:1D:D8", "Microsoft"}, {"00:22:48", "Microsoft"},
            {"00:50:F2", "Microsoft"}, {"28:18:78", "Microsoft"}, {"28:EE:52", "Microsoft"},
            {"50:1A:C5", "Microsoft"}, {"7C:1E:52", "Microsoft"},
            // Lenovo
            {"00:09:2D", "Lenovo"}, {"00:25:B3", "Lenovo"}, {"04:5B:ED", "Lenovo"},
            {"08:3E:8E", "Lenovo"}, {"0C:4D:E9", "Lenovo"}, {"10:02:B5", "Lenovo"},
            {"14:13:33", "Lenovo"}, {"28:D2:44", "Lenovo"}, {"28:F3:66", "Lenovo"},
            {"30:10:B3", "Lenovo"}, {"3C:97:0E", "Lenovo"}, {"40:2C:76", "Lenovo"},
            {"40:74:E0", "Lenovo"}, {"44:37:E6", "Lenovo"}, {"48:FB:49", "Lenovo"},
            {"4C:B1:99", "Lenovo"}, {"54:EE:75", "Lenovo"}, {"60:02:92", "Lenovo"},
            {"60:57:18", "Lenovo"}, {"70:5A:0F", "Lenovo"}, {"74:86:7A", "Lenovo"},
            {"78:2B:CB", "Lenovo"}, {"78:92:9C", "Lenovo"}, {"80:5E:C0", "Lenovo"},
            {"84:2B:2B", "Lenovo"}, {"88:70:8C", "Lenovo"}, {"90:7F:61", "Lenovo"},
            {"94:65:9C", "Lenovo"}, {"98:DC:44", "Lenovo"}, {"A0:48:1C", "Lenovo"},
            // Dell
            {"00:06:5B", "Dell"}, {"00:08:74", "Dell"}, {"00:0B:DB", "Dell"},
            {"00:0D:56", "Dell"}, {"00:0F:1F", "Dell"}, {"00:11:43", "Dell"},
            {"00:12:3F", "Dell"}, {"00:13:72", "Dell"}, {"00:14:22", "Dell"},
            {"00:15:C5", "Dell"}, {"00:16:F0", "Dell"}, {"00:18:8B", "Dell"},
            {"00:19:B9", "Dell"}, {"00:1A:A0", "Dell"}, {"00:1C:23", "Dell"},
            {"00:1D:09", "Dell"}, {"00:1E:4F", "Dell"}, {"00:1F:D0", "Dell"},
            {"00:21:70", "Dell"}, {"00:22:19", "Dell"}, {"00:23:AE", "Dell"},
            {"00:24:E8", "Dell"}, {"00:25:64", "Dell"}, {"00:26:B9", "Dell"},
            // ASUS
            {"00:01:2E", "ASUS"}, {"00:04:0E", "ASUS"}, {"00:0C:6E", "ASUS"},
            {"00:0E:A6", "ASUS"}, {"00:11:2F", "ASUS"}, {"00:13:D4", "ASUS"},
            {"00:15:F2", "ASUS"}, {"00:17:31", "ASUS"}, {"00:18:F3", "ASUS"},
            {"00:1A:92", "ASUS"}, {"00:1B:FC", "ASUS"}, {"00:1D:60", "ASUS"},
            {"00:1E:8C", "ASUS"}, {"00:1F:C6", "ASUS"}, {"00:22:15", "ASUS"},
            {"00:23:54", "ASUS"}, {"00:24:8C", "ASUS"}, {"00:26:18", "ASUS"},
            {"10:BF:48", "ASUS"}, {"14:DA:E9", "ASUS"}, {"1C:87:2C", "ASUS"},
            {"20:CF:30", "ASUS"}, {"2C:56:DC", "ASUS"}, {"2C:FD:A1", "ASUS"},
            {"30:5A:3A", "ASUS"}, {"38:2C:4A", "ASUS"}, {"40:16:7E", "ASUS"},
            {"40:87:9C", "ASUS"}, {"4C:ED:FB", "ASUS"}, {"50:46:5D", "ASUS"},
            {"54:04:A6", "ASUS"}, {"54:A0:50", "ASUS"}, {"60:45:CB", "ASUS"},
            {"60:A4:4C", "ASUS"}, {"6C:62:6D", "ASUS"}, {"74:D0:2B", "ASUS"},
            {"78:24:AF", "ASUS"}, {"7C:10:C9", "ASUS"}, {"7C:B0:C2", "ASUS"},
            {"90:E6:BA", "ASUS"},
        };
        return table;
    }

    // ─── MAC Format ──────────────────────────────────────────────────────────
    std::string FormatMAC(const uint8_t* mac_bytes) {
        std::ostringstream ss;
        for (int i = 0; i < 6; ++i) {
            if (i) ss << ":";
            ss << std::uppercase << std::hex << std::setfill('0')
               << std::setw(2) << static_cast<int>(mac_bytes[i]);
        }
        return ss.str();
    }

    // ─── Vendor Lookup ───────────────────────────────────────────────────────
    std::string LookupVendor(const uint8_t* mac_bytes) {
        std::ostringstream oui;
        oui << std::uppercase << std::hex << std::setfill('0')
            << std::setw(2) << static_cast<int>(mac_bytes[0]) << ":"
            << std::setw(2) << static_cast<int>(mac_bytes[1]) << ":"
            << std::setw(2) << static_cast<int>(mac_bytes[2]);

        const auto& table = GetVendorTable();
        auto it = table.find(oui.str());
        if (it != table.end()) return it->second;
        return "";
    }

    // ─── OS Fingerprint (User-Agent'tan) ─────────────────────────────────────
    std::string GuessOS(const std::string& ua) {
        if (ua.empty()) return "";

        // Küçük harfe çevir arama için
        std::string ual = ua;
        std::transform(ual.begin(), ual.end(), ual.begin(), ::tolower);

        if (ual.find("iphone")    != std::string::npos) return "iOS (iPhone)";
        if (ual.find("ipad")      != std::string::npos) return "iOS (iPad)";
        if (ual.find("ipod")      != std::string::npos) return "iOS (iPod)";
        if (ual.find("macintosh") != std::string::npos || ual.find("mac os x") != std::string::npos) return "macOS";
        if (ual.find("android")   != std::string::npos) {
            // Android versiyonunu bulmaya çalış
            auto pos = ua.find("Android ");
            if (pos != std::string::npos && pos + 8 < ua.size()) {
                auto end = ua.find(';', pos + 8);
                if (end == std::string::npos) end = ua.find(')', pos + 8);
                if (end != std::string::npos) {
                    return "Android " + ua.substr(pos + 8, end - pos - 8);
                }
            }
            return "Android";
        }
        if (ual.find("windows phone") != std::string::npos) return "Windows Phone";
        if (ual.find("windows nt 10") != std::string::npos) return "Windows 10/11";
        if (ual.find("windows nt 6.3") != std::string::npos) return "Windows 8.1";
        if (ual.find("windows nt 6.2") != std::string::npos) return "Windows 8";
        if (ual.find("windows nt 6.1") != std::string::npos) return "Windows 7";
        if (ual.find("windows")   != std::string::npos) return "Windows";
        if (ual.find("linux")     != std::string::npos) return "Linux";
        if (ual.find("ubuntu")    != std::string::npos) return "Ubuntu";
        if (ual.find("fedora")    != std::string::npos) return "Fedora";
        if (ual.find("cros")      != std::string::npos) return "ChromeOS";
        if (ual.find("playstation") != std::string::npos) return "PlayStation";
        if (ual.find("xbox")      != std::string::npos) return "Xbox";
        if (ual.find("smart-tv")  != std::string::npos) return "Smart TV";
        if (ual.find("tizen")     != std::string::npos) return "Tizen (Samsung TV)";
        if (ual.find("webos")     != std::string::npos) return "WebOS (LG TV)";
        if (ual.find("nintendo")  != std::string::npos) return "Nintendo";
        if (ual.find("roku")      != std::string::npos) return "Roku";

        return "";
    }

    // ─── Browser Çıkar ───────────────────────────────────────────────────────
    std::string ExtractBrowser(const std::string& ua) {
        if (ua.empty()) return "";
        std::string ual = ua;
        std::transform(ual.begin(), ual.end(), ual.begin(), ::tolower);

        if (ual.find("edg/")    != std::string::npos) return "Edge";
        if (ual.find("opr/")    != std::string::npos) return "Opera";
        if (ual.find("opera")   != std::string::npos) return "Opera";
        if (ual.find("chrome/") != std::string::npos) return "Chrome";
        if (ual.find("firefox/") != std::string::npos) return "Firefox";
        if (ual.find("safari/")  != std::string::npos) return "Safari";
        if (ual.find("msie")     != std::string::npos) return "IE";
        if (ual.find("trident/") != std::string::npos) return "IE";
        if (ual.find("curl")     != std::string::npos) return "curl";
        if (ual.find("python")   != std::string::npos) return "Python";
        if (ual.find("java/")    != std::string::npos) return "Java HTTP";
        if (ual.find("dalvik")   != std::string::npos) return "Android App";
        if (ual.find("okhttp")   != std::string::npos) return "OkHttp (Android App)";
        if (ual.find("cfnetwork") != std::string::npos) return "iOS App";

        return "Bilinmiyor";
    }

    // ─── IP Format ───────────────────────────────────────────────────────────
    std::string FormatIP(uint32_t ip_net) {
        // ip_net is in network byte order (big-endian)
        struct in_addr addr;
        addr.s_addr = ip_net;
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return std::string(buf);
    }
}
