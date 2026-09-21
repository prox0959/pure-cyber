# PureCyber — Pasif Ağ Trafiği & Protokol Analizörü (C++ / Npcap)

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6.svg)](https://microsoft.com)
[![Npcap](https://img.shields.io/badge/Driver-Npcap%20SDK-orange.svg)](https://npcap.com/)
[![CMake](https://img.shields.io/badge/Build-CMake-brightgreen.svg)](https://cmake.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

PureCyber; yerel ağ adaptörleri üzerinden akan ham paketleri (raw Ethernet frames) sürücü (driver) seviyesinde yakalayan, çok katmanlı OSI protokol analizi gerçekleştiren ve şüpheli/açık veri sızıntılarını gerçek zamanlı raporlayan modüler bir pasif ağ dinleme (network sniffing) ve adli bilişim (digital forensics) aracıdır.

---

> ⚠️ **YASAL VE ETİK UYARI (DISCLAIMER):**  
> Bu yazılım yalnızca akademik araştırma, siber güvenlik eğitimi ve ağ yöneticilerinin yetkili güvenlik testleri (penetration testing) için geliştirilmiştir. Yetkisiz ağ trafiğini dinlemek veya kaydetmek bilişim suçları mevzuatı kapsamında cezai sorumluluk doğurabilir. Yazar, yazılımın kötüye kullanımından sorumlu tutulamaz.

---

## 🌟 Öne Çıkan Yetenekler

* **Düşük Seviye Paket Yakalama:** WinPcap / Npcap sürücüsü ve optimize edilmiş BPF (Berkeley Packet Filter) motoru ile sıfır soket yüküyle pasif paket filtreleme.
* **Katmanlı Protokol Çözümleme (Parsing):**
  * `L2 (Ethernet)`: MAC adres ayrıştırma ve OUI tabanlı donanım üreticisi (Vendor Lookup - Apple, Samsung, Intel vb.) tespiti.
  * `L3 (IPv4)`: Paket boyutu, IP başlıkları, TTL kontrolü ve IHL analizi.
  * `L4 (TCP/UDP)`: Port eşleştirme, TCP bayrakları (SYN, ACK, FIN, PSH) ve akış kontrolü.
  * `L7 (Uygulama Katmanı)`:
    * **HTTP/1.x**: Metotlar (`GET`, `POST`, `PUT`, `DELETE`), Host, User-Agent, Referer, Cookie ve Content-Type ayrıştırma.
    * **DNS**: UDP 53 üzerindeki sorgulanan domain isimlerinin (A/AAAA query) dinamik decode edilmesi.
    * **TLS SNI Sniffing**: Şifrelenmiş HTTPS (Port 443/8443) oturumlarında `TLS ClientHello` paketi içerisindeki şifresiz *Server Name Indication* uzantısını ayrıştırarak hedef alan adını ve TLS versiyonunu (`TLS 1.2`, `TLS 1.3`) çözümleme.
* **Cihaz & İşletim Sistemi Parmak İzi (OS Fingerprinting):** User-Agent dizgelerinden ve paket özelliklerinden istemcinin OS (`Windows`, `macOS`, `iOS`, `Android`, `Linux`) ve tarayıcı sürümünü otomatik çıkarma.
* **Güvenlik & Zafiyet Tespiti (Credential Harvester):** Şifrelenmemiş HTTP POST form verilerindeki (`application/x-www-form-urlencoded` ve `application/json`) kimlik bilgilerini (parola, e-posta, token, session) regex/manual parser ile yakalama.
* **Olay Raporlama (SIEM / Webhook Entegrasyonu):** `WinINet` API kullanılarak harici HTTP endpoint'lerine ve Discord sunucularına yapılandırılabilir throttle (cooldown) ile anlık zenginleştirilmiş embed/JSON raporlama.
* **Adli Loglama:** Yakalanan oturumların zaman damgasıyla CSV formatında `capture.log` dosyasına kalıcı kaydı.

---

## 🏗 Mimari Yapı

Proje tek parça (monolithic) yerine endüstri standardı modüler bir mimariyle tasarlanmıştır:

```
pure cyber/
├── CMakeLists.txt         # Çapraz derleme ve Npcap SDK bağlama kuralları
├── config.hpp             # BPF filtreleri, webhook ve çalışma zamanı yapılandırması
├── main.cpp               # CLI argüman işleme, sinyal yakalama (SIGINT)
├── setup.ps1              # Otomatik Npcap/SDK kurulum scripti
├── src/
│   ├── capture.cpp/.hpp   # pcap döngüsü (pcap_loop), interface seçimi ve metrikler
│   ├── parser.cpp/.hpp    # Ethernet, IP, TCP/UDP ve HTTP başlık ayrıştırıcı
│   ├── tls_sniffer.cpp/.hpp # TLS ClientHello paketinden SNI domain ve sürüm çıkarıcı
│   ├── credential.cpp/.hpp  # HTTP POST gövdesinden şifre/form verisi çıkarma ve URL decode
│   ├── device_info.cpp/.hpp # MAC OUI veritabanı eşleştirmesi ve User-Agent analizi
│   ├── webhook.cpp/.hpp   # Windows WinINet API ile asenkron webhook gönderimi
│   └── display.cpp/.hpp   # ANSI destekli renkli CLI konsol arayüzü
```

---

## 🚀 Kurulum ve Derleme

### Gereksinimler
* Windows 10 veya Windows 11 (x64)
* Visual Studio 2022 (C++ Masaüstü Geliştirme Paketi ile)
* CMake 3.16 veya üzeri
* [Npcap Driver](https://npcap.com/#download) (WinPcap API-compatible mode seçilmelidir)
* [Npcap SDK](https://npcap.com/#download) (`npcap-sdk/` klasörüne yerleştirilir)

### 1. Otomatik Kurulum (PowerShell - Yönetici Olarak)
```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1
```

### 2. Manuel Derleme (CMake)
```powershell
mkdir build
cd build
cmake .. -A x64
cmake --build . --config Release
```
Derleme çıktısı: `build\Release\purecyber.exe`

---

## 💻 Kullanım Örnekleri

> ⚠️ Paket yakalama işlemi işletim sisteminde sürücü seviyesinde yetki gerektirdiğinden terminali **Yönetici (Run as Administrator)** olarak açınız.

```powershell
# 1. Mevcut ağ kartlarını ve açıklamalarını listele
.\purecyber.exe --list

# 2. Otomatik kart seçimi ile doğrudan dinlemeyi başlat
.\purecyber.exe

# 3. Belirli bir arayüzü seç (Örn: #2 nolu kart)
.\purecyber.exe 2

# 4. Yakalanan HTTP/TLS olaylarını Discord Webhook'una anlık ilet
.\purecyber.exe --webhook https://discord.com/api/webhooks/xxxx/yyyy

# 5. HTTP gövdesini (Payload) terminalde de göster
.\purecyber.exe --payload

# 6. Sadece webhook çalışsın, terminal çıktısını sessize al
.\purecyber.exe --webhook https://discord.com/api/webhooks/xxxx/yyyy --silent
```

---

## 🛡 Gelecek Geliştirmeler (Roadmap)

- [ ] IPv6 tam başlık desteği
- [ ] ARP Spoofing / Man-in-the-Middle (MitM) simülasyon modülü
- [ ] PCAP dosyalarını kaydetme (`pcap_dump`) ve Wireshark uyumlu dışa aktarma
- [ ] Çoklu iş parçacığı (Multi-threaded) paket işleme kuyruğu (Producer-Consumer Queue)

---

## 📜 Lisans
Bu proje [MIT Lisansı](LICENSE) altında korunmaktadır.
