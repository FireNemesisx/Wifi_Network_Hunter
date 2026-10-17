# Network Hunter: Hibrit Ağ Varlık & Saldırı Yüzeyi Yöneticisi

Yerel ağ keşfi (L2/L3), varlık envanteri yönetimi ve hibrit (pasif + aktif) istihbarat için tasarlanmış yüksek performanslı, modüler ve olay güdümlü (event-driven) bir masaüstü uygulamasıdır. **Python 3.11+**, **PyQt6**, **Scapy** ve asenkron korelasyon veri yolu üzerine inşa edilmiştir.

---

## 1. Temel Felsefe: Sıfır-Temas Pasif Öncelikli (Zero-Touch Passive First)

Network Hunter, **Sıfır-Temas Pasif Öncelikli** operasyon doktriniyle çalışır:
- Yerel yayın etki alanındaki (broadcast domain) paketleri (ARP, DHCP Option 55, mDNS, NetBIOS, LLMNR) ağa hiçbir ek paket göndermeksizin arka planda dinler ve varlıkları sessizce tespit eder.
- Aktif tarama operasyonları (L2 ARP broadcast taraması, hedefli SYN/TCP taraması, TTL incelemesi ve servis banner yakalama) yalnızca **istek üzerine**, **hız sınırlamalı** (en fazla 100 paket/saniye tavanı) ve **adaptif** olarak icra edilir. Bu sayede kablosuz ağ kilitlenmeleri ve IDS/IPS alarmları engellenir.

---

## 2. Sistem Mimarisi

```
+-----------------------------------------------------------------------+
|                             AĞ TRAFİĞİ (L2 / L3)                      |
+-----------------------------------+-----------------------------------+
                                    |
          +-------------------------+-------------------------+
          |                                                   |
          v                                                   v
+-------------------+                               +-------------------+
|  PASİF SNIFFER    |                               |   AKTİF MOTOR     |
| (Sıfır-Temas Dinleme)                             | (Adaptif Tarama)  |
+---------+---------+                               +---------+---------+
          |                                                   |
          +-------------------------+-------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                    KORELASYON & TEKİLLEŞTİRME MOTORU                  |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                    DURUM YÖNETİMİ & YEREL ÖNBELLEK                    |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                       PyQt6 THREAD-SAFE SOC ARAYÜZÜ                   |
+-----------------------------------------------------------------------+
```

### Modül A: Sıfır-Temas Pasif Sniffer (`core/sniffer.py`)
- **ARP Trafiği:** IP-MAC eşleşmelerini anında yakalar ve yeni gelen cihazları kaydeder.
- **DHCP Option 55 (`Parameter Request List`) & Option 12:** DHCP İstek paketlerindeki parametre dizilimlerini analiz ederek işletim sistemini (Windows, macOS/iOS, Linux, Android, IoT) ve bilgisayar adını (Hostname) doğrudan tespit eder.
- **mDNS / Bonjour (UDP 5353):** Apple cihazları, akıllı TV'ler, IoT donanımları ve yerel servis deklarasyonlarını yakalar.
- **NetBIOS / LLMNR (UDP 137 / 5355):** Windows çalışma grupları ve Active Directory bilgisayar adlarını çözümler.
- **Adaptif Geri Çekilme:** Yönetici yetkisi veya Npcap bulunmadığında işletim sistemi kernel ARP tablosunu ve yayın soketlerini dinlemeyi sürdürür.

### Modül B: Adaptif Aktif Keşif Motoru (`core/scanner.py`)
- **L2 Ağ Taraması:** Subnet (/24) genelinde hızlı ARP ve çok iş parçacıklı bağlantı problarıyla canlı cihazları ~2 saniyede keşfeder.
- **Hedefli Port Taraması:** Yalnızca canlı olduğu doğrulanan varlıkların kritik 20 portunu (`21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443`) yoklar.
- **ICMP / TTL İncelemesi:** Gecikme süresini (RTT) ölçer ve TTL değerinden (`TTL <= 64` -> Linux/Apple, `TTL <= 128` -> Windows, `TTL <= 255` -> Cisco/Ağ Altyapısı) işletim sistemini tahmin eder.
- **Banner Grabbing:** Açık portlarla el sıkışma gerçekleştirerek servis ve sürüm bilgilerini çeker.
- **Hız Sınırlaması (PPS Cap):** Ağ tıkanıklığını ve router donmalarını önlemek için saniyede maksimum 100 paket limitini sıkı şekilde korur.

### Modül C: Veri Korelasyon ve Tekilleştirme Motoru (`core/correlation.py`)
Farklı kaynaklardan gelen verileri katı bir öncelik hiyerarşisiyle birleştirir:
1. **IP & MAC Adresi:** L2 ARP / Pasif ARP verisine tam güven (%100 yerel doğruluk).
2. **Cihaz Adı (Hostname):** Pasif mDNS / NetBIOS / DHCP Option 12 verisi DNS sorgusuna göre önceliklidir.
3. **İşletim Sistemi:** Pasif DHCP Option 55 imzası en yüksek önceliktedir; ardından TTL ve port imzaları değerlendirilir.
4. **Açık Portlar:** Aktif tarama sonuçları esastır.
5. **Kalıcılık:** Ağ taban çizgisini `assets_cache.json` dosyasına güvenle kaydeder.

### Modül D: Güvenlik ve Anomali Tespit Motoru (`core/security.py`)
- **Yabancı (Rogue) Cihaz Alarmı:** Yerel önbellekte geçmiş kaydı bulunmayan her yeni MAC adresini tespit eder ve yüksek öncelikli alarm üretir.
- **ARP Spoofing / MitM Dedektörü:** Tek bir MAC adresinin 15 saniye içinde birden fazla IP adresini sahiplenmesini yakalar.
- **Ağ Geçidi Değişimi Alarmı:** Varsayılan ağ geçidinin (Router) MAC adresi değiştiğinde **KRİTİK** alarm tetikler.
- **Varsayılan Kimlik Bilgisi Denetimi:** Keşfedilen web yönetim arayüzlerinde yaygın fabrika parolalarını (`admin:admin`, `root:root`) güvenle test eder.

---

## 3. Proje Dizin Yapısı

```
Network_Hunter/
├── core/
│   ├── __init__.py
│   ├── models.py              # DeviceAsset, SecurityAlert, ScanConfig veri modelleri
│   ├── oui_lookup.py          # Hızlı bellek-içi MAC OUI ve Özel Wi-Fi MAC veritabanı
│   ├── sniffer.py             # Modül A: Pasif paket dinleme iş parçacığı (QThread)
│   ├── scanner.py             # Modül B: Aktif tarama ve banner yakalama (QThread)
│   ├── correlation.py         # Modül C: Durum yönetimi, tekilleştirme & öncelik motoru
│   └── security.py            # Modül D: Rogue cihaz & ARP spoofing tespit motoru
├── gui/
│   ├── __init__.py
│   ├── main_window.py         # PyQt6 Ana SOC Penceresi
│   ├── topology_widget.py     # 60 FPS İnteraktif Radyal Ağ Topolojisi Haritası
│   ├── alerts_widget.py       # Gerçek zamanlı Güvenlik Alarmları Çekmecesi & JSON Dışa Aktarma
│   ├── device_detail_widget.py# Ayrıntılı Cihaz İnceleme Paneli (DHCP Opt 55, Bannerlar)
│   └── styles.py              # Cyberpunk karanlık tema (QSS) ve renk paletleri
├── utils/
│   ├── __init__.py
│   ├── network_info.py        # Ağ arayüzleri, varsayılan ağ geçidi, sistem ARP tablosu
│   └── privileges.py          # Windows Administrator / Linux root / Npcap yetki denetimi
├── tests/
│   └── test_core.py           # Otomatik birim test paketi (7/7 test başarılı)
├── main.py                    # Uygulama başlatıcı
├── requirements.txt           # Python bağımlılıkları
├── .gitignore                 # Git yoksayma kuralları
└── README.md                  # Proje dokümantasyonu
```

---

## 4. Kurulum ve Gereksinimler

### Ön Koşullar
- **Python 3.11+**
- **Windows:** Tam paket yakalama için [Npcap](https://npcap.com) kurulu olması önerilir (*"WinPcap API-compatible Mode"* seçeneğiyle).
- **Linux:** `libpcap-dev` ve ham soket yetkileri (`CAP_NET_RAW`).

### Bağımlılıkların Yüklenmesi
```bash
pip install -r requirements.txt
```

---

## 5. Uygulamayı Çalıştırma

### Yönetici İzinleriyle Çalıştırma (Önerilen)
Windows üzerinde terminali **"Yönetici olarak çalıştır"** ile açtıktan sonra:
```bash
python main.py
```

Linux üzerinde:
```bash
sudo python main.py
```

### Adaptif Geri Çekilme Modu (Standart Kullanıcı)
Yönetici izni veya Npcap olmadan başlatıldığında Network Hunter çökmek yerine otomatik olarak **Adaptif Geri Çekilme Modu**na geçer:
- İşletim sisteminin kernel ARP tablosunu anında tarayarak canlı cihazları listeler.
- Aktif taramaları standart soket bağlantıları ve çok iş parçacıklı havuz üzerinden yürütür.
- Kullanıcıya yönetici yetkilerini nasıl açabileceğine dair bilgilendirme afişi gösterir.

---

## 6. Testleri Çalıştırma

Çekirdek motorların işleyişini doğrulamak için birim testleri çalıştırabilirsiniz:
```bash
python -m unittest tests/test_core.py
```
