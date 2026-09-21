#include "credential.hpp"
#include "parser.hpp"
#include <algorithm>
#include <sstream>
#include <cctype>

// ============================================================
//  credential.cpp — HTTP POST form/JSON credential çıkarma
// ============================================================

namespace Credential {

    // ─── Hassas field listesi ─────────────────────────────────────────────────
    // Bunlardan biri bulunursa has_sensitive = true olur
    const std::vector<std::string> SENSITIVE_FIELDS = {
        "password", "passwd", "pass", "pwd", "secret",
        "token", "api_key", "apikey", "api-key", "access_token",
        "auth", "authorization", "credential",
        "pin", "otp", "code", "verification_code",
        "ssn", "social_security", "card_number", "cvv", "cvc",
        "credit_card", "cc_number", "expiry", "exp_date",
        "private_key", "session", "session_token", "cookie",
        "refresh_token", "id_token", "bearer",
        // Türkçe field adları (Türk siteleri için)
        "sifre", "şifre", "parola", "gizli", "dogrulama",
    };

    // ─── Hassas field kontrolü ────────────────────────────────────────────────
    bool IsSensitiveField(const std::string& field_name) {
        std::string lower = field_name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        for (const auto& sf : SENSITIVE_FIELDS) {
            if (lower.find(sf) != std::string::npos) return true;
        }
        return false;
    }

    // ─── URL Decode ───────────────────────────────────────────────────────────
    std::string URLDecode(const std::string& s) {
        std::string result;
        result.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '%' && i + 2 < s.size()) {
                // %XX → char
                char hex[3] = { s[i+1], s[i+2], 0 };
                char* end;
                long val = strtol(hex, &end, 16);
                if (end == hex + 2) {
                    result += (char)val;
                    i += 2;
                } else {
                    result += s[i];
                }
            } else if (s[i] == '+') {
                result += ' ';
            } else {
                result += s[i];
            }
        }
        return result;
    }

    // ─── application/x-www-form-urlencoded Parse ──────────────────────────────
    std::unordered_map<std::string, std::string> ParseFormEncoded(const std::string& body) {
        std::unordered_map<std::string, std::string> fields;
        std::istringstream ss(body);
        std::string pair;

        while (std::getline(ss, pair, '&')) {
            auto eq = pair.find('=');
            if (eq == std::string::npos) continue;

            std::string key = URLDecode(pair.substr(0, eq));
            std::string val = URLDecode(pair.substr(eq + 1));

            // Boş key atla
            if (key.empty()) continue;

            // Val'i kısalt (çok uzunsa)
            if (val.size() > 256) val = val.substr(0, 256) + "...[truncated]";

            fields[key] = val;
        }
        return fields;
    }

    // ─── JSON Parse (basit, regex yok) ───────────────────────────────────────
    // Sadece flat "key":"value" veya "key":value çiftlerini yakalar
    // Nested object/array'leri tam parse etmez ama credential field'ları genellikle flat
    std::unordered_map<std::string, std::string> ParseJSON(const std::string& body) {
        std::unordered_map<std::string, std::string> fields;

        size_t pos = 0;
        while (pos < body.size()) {
            // Key: "..." ara
            auto key_start = body.find('"', pos);
            if (key_start == std::string::npos) break;

            auto key_end = body.find('"', key_start + 1);
            if (key_end == std::string::npos) break;

            std::string key = body.substr(key_start + 1, key_end - key_start - 1);

            // ':' ara
            pos = key_end + 1;
            while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\n' || body[pos] == '\r')) ++pos;
            if (pos >= body.size() || body[pos] != ':') continue;
            ++pos;
            while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) ++pos;

            if (pos >= body.size()) break;

            std::string val;
            if (body[pos] == '"') {
                // String value
                ++pos;
                auto val_end = body.find('"', pos);
                if (val_end == std::string::npos) break;
                val = body.substr(pos, val_end - pos);
                pos = val_end + 1;
            } else {
                // Number/bool/null
                size_t val_end = pos;
                while (val_end < body.size() && body[val_end] != ',' && body[val_end] != '}' && body[val_end] != '\n') {
                    ++val_end;
                }
                val = body.substr(pos, val_end - pos);
                // Trim
                while (!val.empty() && std::isspace((unsigned char)val.back())) val.pop_back();
                pos = val_end;
            }

            if (!key.empty()) {
                if (val.size() > 256) val = val.substr(0, 256) + "...[truncated]";
                fields[key] = val;
            }
        }

        return fields;
    }

    // ─── Ana çıkarma fonksiyonu ───────────────────────────────────────────────
    bool Extract(
        const std::string& http_raw,
        const std::string& src_ip,
        const std::string& src_mac,
        const std::string& vendor,
        const std::string& host,
        const std::string& path,
        CredEntry& out
    ) {
        // Sadece POST (ve PUT, PATCH) metodlarına bak
        bool is_post = (http_raw.substr(0, 5) == "POST " ||
                        http_raw.substr(0, 4) == "PUT " ||
                        http_raw.substr(0, 6) == "PATCH ");
        if (!is_post) return false;

        // Body'yi bul (header'lardan sonra)
        auto body_pos = http_raw.find("\r\n\r\n");
        if (body_pos == std::string::npos) {
            body_pos = http_raw.find("\n\n");
            if (body_pos == std::string::npos) return false;
            body_pos += 2;
        } else {
            body_pos += 4;
        }

        if (body_pos >= http_raw.size()) return false;
        std::string body = http_raw.substr(body_pos);
        if (body.empty()) return false;

        // Content-Type'a bak
        std::string content_type = Parser::ExtractHTTPHeader(http_raw, "Content-Type");
        std::string ct_lower = content_type;
        std::transform(ct_lower.begin(), ct_lower.end(), ct_lower.begin(), ::tolower);

        std::unordered_map<std::string, std::string> fields;

        if (ct_lower.find("x-www-form-urlencoded") != std::string::npos) {
            fields = ParseFormEncoded(body);
        } else if (ct_lower.find("json") != std::string::npos) {
            fields = ParseJSON(body);
        } else if (ct_lower.find("multipart") != std::string::npos) {
            // Multipart'ta sadece text field'larına bak
            // Basit yaklaşım: form-like field'ları bul
            // Content-Disposition: form-data; name="username"
            size_t p = 0;
            while ((p = body.find("name=\"", p)) != std::string::npos) {
                p += 6;
                auto name_end = body.find('"', p);
                if (name_end == std::string::npos) break;
                std::string fname = body.substr(p, name_end - p);
                p = name_end + 1;

                // Bir sonraki satıra geç (boş satır = value başlangıcı)
                auto val_start = body.find("\r\n\r\n", p);
                if (val_start == std::string::npos) val_start = body.find("\n\n", p);
                if (val_start == std::string::npos) break;
                val_start += 4;

                // Değer: bir sonraki boundary'ye kadar
                auto val_end = body.find("\r\n--", val_start);
                if (val_end == std::string::npos) val_end = body.find("\n--", val_start);
                if (val_end == std::string::npos) val_end = body.size();

                std::string fval = body.substr(val_start, val_end - val_start);
                if (!fname.empty() && fval.size() < 512) {
                    fields[fname] = fval;
                }
            }
        } else {
            // Content-Type yok veya bilinmiyor — yine de form parse dene
            if (body.find('=') != std::string::npos && body.find('{') == std::string::npos) {
                fields = ParseFormEncoded(body);
            } else if (body.find('{') != std::string::npos) {
                fields = ParseJSON(body);
            }
        }

        if (fields.empty()) return false;

        // Hassas field var mı?
        for (const auto& [k, v] : fields) {
            if (IsSensitiveField(k)) {
                out.has_sensitive = true;
                break;
            }
        }

        out.fields       = std::move(fields);
        out.src_ip       = src_ip;
        out.src_mac      = src_mac;
        out.vendor       = vendor;
        out.host         = host;
        out.path         = path;
        out.content_type = content_type;

        return true;
    }
}
