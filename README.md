# PureCyber — Passive Network Traffic & Protocol Analyzer (C++ / Npcap)

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6.svg)](https://microsoft.com)
[![Npcap](https://img.shields.io/badge/Driver-Npcap%20SDK-orange.svg)](https://npcap.com/)
[![CMake](https://img.shields.io/badge/Build-CMake-brightgreen.svg)](https://cmake.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v1.0.0-brightgreen.svg)](https://github.com/prox0959/pure-cyber/releases)
[![Status](https://img.shields.io/badge/Status-Completed-success.svg)](#)

---

### [TR] Proje Özeti & Durum

> 📌 **PROJE DURUMU:** Bu proje tamamlanmış (finalized/archive) bir referans çalışmasıdır. Aktif olarak yeni özellik eklenmeyecek olup, 15 yaşımda modern C++ ve düşük seviyeli ağ programlama (low-level network programming) alanındaki yetkinliğimi pekiştirmek amacıyla geliştirilmiş nihai sürümdür.

PureCyber; yerel ağ adaptörleri üzerinden akan ham paketleri (raw Ethernet frames) sürücü (driver) seviyesinde yakalayan, çok katmanlı OSI protokol analizi gerçekleştiren ve şüpheli/açık veri sızıntılarını gerçek zamanlı raporlayan modüler bir pasif ağ dinleme (network sniffing) ve adli bilişim (digital forensics) aracıdır.

> ⚠️ **YASAL VE ETİK UYARI (DISCLAIMER):**  
> Bu yazılım yalnızca akademik araştırma, siber güvenlik eğitimi ve ağ yöneticilerinin yetkili güvenlik testleri (penetration testing) için geliştirilmiştir. Yetkisiz ağ trafiğini dinlemek veya kaydetmek bilişim suçları mevzuatı kapsamında cezai sorumluluk doğurabilir. Yazar, yazılımın kötüye kullanımından sorumlu tutulamaz.

#### 🌟 Yetenekler
* **Düşük Seviye Paket Yakalama:** WinPcap / Npcap sürücüsü ve optimize edilmiş BPF (Berkeley Packet Filter) motoru ile sıfır soket yüküyle pasif paket filtreleme.
* **Katmanlı Protokol Çözümleme (Parsing):**
  * `L2 (Ethernet)`: MAC adres ayrıştırma ve OUI tabanlı donanım üreticisi (Vendor Lookup - Apple, Samsung, Intel vb.) tespiti.
  * `L3 (IPv4)`: Paket boyutu, IP başlıkları, TTL kontrolü ve IHL analizi.
  * `L4 (TCP/UDP)`: Port eşleştirme, TCP bayrakları (SYN, ACK, FIN, PSH) ve akış kontrolü.
  * `L7 (Uygulama Katmanı)`:
    * **HTTP/1.x**: Metotlar (`GET`, `POST`, `PUT`, `DELETE`), Host, User-Agent, Referer, Cookie ve Content-Type ayrıştırma.
    * **DNS**: UDP 53 üzerindeki sorgulanan domain isimlerinin dinamik decode edilmesi.
    * **TLS SNI Sniffing**: Şifrelenmiş HTTPS (Port 443/8443) oturumlarında `TLS ClientHello` paketi içerisindeki şifresiz *Server Name Indication* uzantısını ayrıştırarak hedef alan adını ve TLS versiyonunu (`TLS 1.2`, `TLS 1.3`) çözümleme.
* **Cihaz & İşletim Sistemi Parmak İzi (OS Fingerprinting):** User-Agent dizgelerinden ve paket özelliklerinden istemcinin OS (`Windows`, `macOS`, `iOS`, `Android`, `Linux`) ve tarayıcı sürümünü otomatik çıkarma.
* **Güvenlik & Zafiyet Tespiti (Credential Harvester):** Şifrelenmemiş HTTP POST form verilerindeki (`application/x-www-form-urlencoded` ve `application/json`) kimlik bilgilerini (parola, e-posta, token, session) regex/manual parser ile yakalama.
* **Olay Raporlama (SIEM / Webhook Entegrasyonu):** `WinINet` API kullanılarak harici HTTP endpoint'lerine ve Discord sunucularına yapılandırılabilir throttle (cooldown) ile anlık zenginleştirilmiş embed/JSON raporlama.
* **Adli Loglama:** Yakalanan oturumların zaman damgasıyla CSV formatında `capture.log` dosyasına kalıcı kaydı.

---

### [EN] Project Overview & Status

> 📌 **PROJECT STATUS:** This project is a completed, standalone reference build. It is not slated for further active updates or feature additions. It stands as a finalized portfolio demonstration of low-level C++ network engineering, protocol dissection, and telemetry integration.

PureCyber is a high-performance, modular passive network sniffer and digital forensics tool written in modern C++. It intercepts raw Ethernet frames at the driver level using Npcap, performs deep multi-layer OSI protocol parsing, and alerts on plain-text credentials and sensitive traffic leaks in real time.

> ⚠️ **LEGAL & ETHICAL DISCLAIMER:**  
> This software is intended solely for educational purposes, academic research, and authorized penetration testing by network administrators. Intercepting network traffic without explicit consent is illegal. The author assumes no liability for misuse.

#### 🌟 Key Capabilities
* **Kernel-Level Packet Interception:** Seamless raw frame acquisition via Npcap / WinPcap with kernel-level BPF (Berkeley Packet Filter) offloading to eliminate user-space CPU bottlenecks.
* **Multi-Layer Protocol Dissection:**
  * `Layer 2 (Data Link)`: MAC address parsing and OUI vendor fingerprinting (Apple, Samsung, Intel, etc.).
  * `Layer 3 (Network)`: IPv4 header dissection, TTL inspection, IHL verification, and checksum analysis.
  * `Layer 4 (Transport)`: TCP/UDP port mapping, state flag tracking (SYN, ACK, FIN, PSH, RST).
  * `Layer 7 (Application)`:
    * **HTTP/1.x**: Dissecting methods (`GET`, `POST`, `PUT`, `DELETE`), headers (`Host`, `User-Agent`, `Referer`, `Cookie`), and payloads.
    * **DNS**: Dynamic label parsing of domain name queries over UDP port 53.
    * **TLS SNI Extraction**: Inspecting unencrypted *Server Name Indication* (SNI) extensions inside `TLS ClientHello` packets across encrypted HTTPS connections (Port 443/8443) to identify destination hostnames and negotiated protocols (`TLS 1.2`, `TLS 1.3`).
* **Passive OS Fingerprinting:** Heuristic client identification (Windows, Linux, macOS, iOS, Android) and browser identification derived from User-Agent patterns.
* **Credential Leak Detection:** Auditing unencrypted HTTP POST bodies (`application/x-www-form-urlencoded` and `application/json`) for exposed passwords, session tokens, and usernames.
* **Security Telemetry & Webhook Dispatch:** Native Windows `WinINet` implementation for non-blocking alerting to Discord and SIEM webhook endpoints with built-in rate limiting (cooldown).
* **Forensic Logging:** Persistent session recording in CSV-formatted `capture.log`.

---

## 🏗 Architecture / Mimari Yapı

```
pure cyber/
├── CMakeLists.txt         # Build definitions and Npcap SDK linkage
├── config.hpp             # Runtime configuration, BPF filters, webhook settings
├── main.cpp               # CLI entrypoint, argument parsing, signal handling
├── setup.ps1              # Automated setup script for Npcap and SDK
├── src/
│   ├── capture.cpp/.hpp   # Core pcap capture loop (pcap_loop) & thread stats
│   ├── parser.cpp/.hpp    # L2-L7 protocol dissecting engine
│   ├── tls_sniffer.cpp/.hpp # TLS ClientHello SNI and version parser
│   ├── credential.cpp/.hpp  # HTTP POST form field decoding & credential extractor
│   ├── device_info.cpp/.hpp # MAC OUI database lookup & OS fingerprinting
│   ├── webhook.cpp/.hpp   # WinINet asynchronous HTTP POST webhook client
│   └── display.cpp/.hpp   # ANSI color-coded CLI dashboard
```

---

## 🚀 Build & Installation / Kurulum ve Derleme

### Prerequisites / Gereksinimler
* Windows 10 / 11 (x64)
* Visual Studio 2022 (with "Desktop development with C++")
* CMake 3.16+
* [Npcap Driver](https://npcap.com/#download) (Installed in WinPcap API-compatible mode)
* [Npcap SDK](https://npcap.com/#download) (Extracted to `npcap-sdk/`)

### Automated Setup / Otomatik Kurulum (PowerShell as Admin)
```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1
```

### Manual Compilation / Derleme
```powershell
mkdir build
cd build
cmake .. -A x64
cmake --build . --config Release
```
Binary output: `build\Release\purecyber.exe`

---

## 💻 Usage / Kullanım

> ⚠️ Administrator privileges are required to bind to driver-level network interfaces. / *Yönetici hakları gereklidir.*

```powershell
# List network adapters / Ağ kartlarını listele
.\purecyber.exe --list

# Start automatic capture / Otomatik dinleme başlat
.\purecyber.exe

# Select interface by index / Belirli bir adaptörü seç
.\purecyber.exe 2

# Stream alerts to Discord / Discord Webhook ile canlı izle
.\purecyber.exe --webhook https://discord.com/api/webhooks/xxxx/yyyy

# Display HTTP payloads / HTTP gövdesini göster
.\purecyber.exe --payload

# Silent terminal mode (Webhook only) / Sessiz mod
.\purecyber.exe --webhook https://discord.com/api/webhooks/xxxx/yyyy --silent
```

---

## 📜 License / Lisans
This project is open-source under the [MIT License](LICENSE).
