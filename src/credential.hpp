#pragma once
#include <string>
#include <vector>
#include <unordered_map>

// ============================================================
//  credential.hpp — HTTP POST form verisi çıkarma
//
//  application/x-www-form-urlencoded POST body'lerinden
//  hassas field'ları (password, email, token vb.) çıkarır.
//  JSON body'lerden de değer çeker.
// ============================================================

namespace Credential {

    // Çıkarılan credential verisi
    struct CredEntry {
        std::string src_ip;
        std::string src_mac;
        std::string vendor;
        std::string host;
        std::string path;
        std::string content_type;
        std::unordered_map<std::string, std::string> fields;  // field_name → value
        bool has_sensitive = false;  // password/token gibi hassas field var mı?
    };

    // HTTP POST body'sinden credential field'larını çıkar
    // http_body: Content-Type header'dan sonraki body kısmı
    // content_type: "application/x-www-form-urlencoded" veya "application/json" vb.
    bool Extract(
        const std::string& http_raw,
        const std::string& src_ip,
        const std::string& src_mac,
        const std::string& vendor,
        const std::string& host,
        const std::string& path,
        CredEntry& out
    );

    // URL decode (%XX → char)
    std::string URLDecode(const std::string& s);

    // "a=b&c=d" formatını parse et
    std::unordered_map<std::string, std::string> ParseFormEncoded(const std::string& body);

    // Basit JSON key:value çıkarma (regex yerine manual parse)
    std::unordered_map<std::string, std::string> ParseJSON(const std::string& body);

    // Bu field adı hassas mı?
    bool IsSensitiveField(const std::string& field_name);

    // Hassas field listesi (lowercase, prefix match)
    extern const std::vector<std::string> SENSITIVE_FIELDS;
}
