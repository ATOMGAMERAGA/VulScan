# Changelog

Bu dosya VulScan projesindeki tüm önemli değişiklikleri içerir.

Changelog formatı [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) standardını takip eder ve bu proje [Semantic Versioning](https://semver.org/spec/v2.0.0.html) kullanır.

## [Unreleased]

### Planlanan
- REST API desteği
- Database injection testleri
- WebSocket güvenlik kontrolleri
- Docker container desteği
- GraphQL güvenlik testleri
- Authentication bypass testleri
- Business logic flaw detection
- Mobile API testing

## [3.0.0] - 2024-01-15

### Eklenen
- **CVSS v3.1 Skorlaması** - Endüstri standardı risk değerlendirmesi
- **JSON Export** - Otomatizon ve entegrasyon için JSON çıktı desteği
- **HTML Raporu** - Görsel ve interaktif raporlar
- **CWE Mapping** - Güvenlik açığı kategorilendirmesi
- **Çözüm Önerileri** - Kod örnekleri ile detaylı çözüm önerileri
- **Paralel Tarama** - Çoklu thread desteği ile hızlı tarama
- **Akıllı Rate Limiting** - Hedef sistemi zorlamayan akıllı hız sınırlaması
- **Verbose Logging** - Detaylı tarama süreci takibi
- **Flexible Configuration** - Özelleştirilebilir ayarlar
- **SSL/TLS Configuration** - Zayıf şifreleme kontrolü
- **Cookie Security** - Güvensiz cookie yapılandırması kontrolleri

### Güvenlik Açığı Testleri
- SQL Injection - Klasik ve Blind SQL Injection tespiti
- Cross-Site Scripting (XSS) - Reflected ve DOM tabanlı XSS
- Directory Traversal/LFI - Yerel dosya dahil etme açıkları
- Cross-Site Request Forgery (CSRF) - Token eksikliği kontrolü
- Open Redirect - Açık yönlendirme açıkları
- HTTP Security Headers - Eksik güvenlik başlıkları

### Komut Satırı Parametreleri
- `--verbose/-v` - Detaylı çıktı modu
- `--threads/-t` - Paralel thread sayısı ayarlama
- `--timeout` - İstek zaman aşımı kontrolü
- `--output/-o` - JSON çıktı dosyası belirtme
- `--user-agent/-u` - Özel User-Agent belirleme
- `--report` - HTML rapor oluşturma

### Değiştirilen
- Go sürüm gereksinimi 1.19+ olarak güncellendi
- Performans optimizasyonları
- Hata mesajları daha açıklayıcı hale getirildi

## [2.0.0] - 2023-12-01

### Eklenen
- Temel güvenlik açığı tarama işlevselliği
- Basit rapor çıktısı
- Çoklu hedef desteği

### Değiştirilen
- Kod mimarisi yeniden tasarlandı
- Tarama hızı iyileştirildi

## [1.0.0] - 2023-10-15

### Eklenen
- İlk kararlı sürüm
- Temel SQL Injection tespiti
- XSS tespit işlevselliği
- Basit komut satırı arayüzü

---

## Changelog Formatı

### Kategoriler
- **Eklenen** - Yeni özellikler için
- **Değiştirilen** - Mevcut işlevselliğin değişiklikleri için
- **Kaldırılan** - Şimdi kaldırılan özellikler için
- **Düzeltilen** - Hata düzeltmeleri için
- **Güvenlik** - Güvenlik açığı düzeltmeleri için

### Sürüm Numaralandırması
- **Major (X.0.0)** - Uyumsuz API değişiklikleri
- **Minor (x.Y.0)** - Geriye uyumlu işlevsellik ekleme
- **Patch (x.y.Z)** - Geriye uyumlu hata düzeltmeleri

### Bağlantılar ve Referanslar
- [GitHub Releases](https://github.com/ATOMGAMERAGA/VulScan/releases)
- [Issues](https://github.com/ATOMGAMERAGA/VulScan/issues)
- [Pull Requests](https://github.com/ATOMGAMERAGA/VulScan/pulls)
- [Project Wiki](https://github.com/ATOMGAMERAGA/VulScan/wiki)

### Katkıda Bulunanlar
Sürümlerde önemli katkılarda bulunan kişiler:
- [@ATOMGAMERAGA](https://github.com/ATOMGAMERAGA) - Proje kurucusu ve ana geliştirici

---

*Bu changelog dosyası [Keep a Changelog](https://keepachangelog.com/) formatını kullanmaktadır.*
