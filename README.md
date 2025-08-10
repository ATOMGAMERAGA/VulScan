# 🛡️ VulScan v3.0.1 - Advanced Web Security Scanner

[![Go Version](https://img.shields.io/badge/Go-1.19+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Security-First-red?style=for-the-badge&logo=security)](https://github.com/ATOMGAMERAGA/VulScan)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)](https://github.com/ATOMGAMERAGA/VulScan)

> **⚡ Gelişmiş, hızlı ve kapsamlı web güvenlik açığı tarayıcısı**

VulScan v3.0, modern web uygulamalarında yaygın güvenlik açıklarını tespit eden, CVSS skorlaması yapan ve detaylı raporlar üreten açık kaynak güvenlik tarama aracıdır.

## 🌟 Özellikler

### 🔍 Kapsamlı Güvenlik Taraması
- **SQL Injection** - Klasik ve Blind SQL Injection tespiti
- **Cross-Site Scripting (XSS)** - Reflected ve DOM tabanlı XSS
- **Directory Traversal/LFI** - Yerel dosya dahil etme açıkları
- **Cross-Site Request Forgery (CSRF)** - Token eksikliği kontrolü
- **Open Redirect** - Açık yönlendirme açıkları
- **HTTP Security Headers** - Eksik güvenlik başlıkları
- **SSL/TLS Configuration** - Zayıf şifreleme kontrolü
- **Cookie Security** - Güvensiz cookie yapılandırması

### 📊 Gelişmiş Raporlama
- **CVSS v3.1 Skorlaması** - Endüstri standardı risk değerlendirmesi
- **JSON Export** - Otomatizon ve entegrasyon için
- **HTML Raporu** - Görsel ve interaktif raporlar
- **CWE Mapping** - Güvenlik açığı kategorilendirmesi
- **Çözüm Önerileri** - Kod örnekleri ile detaylı çözümler

### ⚡ Performans & Kullanılabilirlik
- **Paralel Tarama** - Çoklu thread desteği
- **Akıllı Rate Limiting** - Hedef sistemi zorlamaz
- **Verbose Logging** - Detaylı tarama süreci takibi
- **Flexible Configuration** - Özelleştirilebilir ayarlar

## 🚀 Hızlı Başlangıç

### Gereksinimler
- **Go 1.19+** (Kurulum: [golang.org](https://golang.org/))
- **İnternet bağlantısı** (Payload güncellemeleri için)

### Kurulum

```bash
# Repository'yi klonlayın
git clone https://github.com/ATOMGAMERAGA/VulScan.git
cd VulScan

# Bağımlılıkları yükleyin
go mod init VulScan
go mod tidy

# Binary'yi derleyin
go build -o vulscan main.go

# Çalıştırma izni verin (Linux/macOS)
chmod +x vulscan
```

### Temel Kullanım

```bash
# Basit tarama
./vulscan http://example.com/page.php?id=1

# Detaylı tarama
./vulscan http://example.com --verbose --threads 10

# Rapor oluşturma
./vulscan http://example.com --output report.json --report
```

## 📖 Kullanım Kılavuzu

### Komut Satırı Seçenekleri

| Parametre | Kısa | Açıklama | Varsayılan |
|-----------|------|----------|------------|
| `--verbose` | `-v` | Detaylı çıktı modu | false |
| `--threads` | `-t` | Paralel thread sayısı | 5 |
| `--timeout` | | İstek zaman aşımı (saniye) | 10 |
| `--output` | `-o` | JSON çıktı dosyası | - |
| `--user-agent` | `-u` | Özel User-Agent | VulScan/3.0 |
| `--report` | | HTML rapor oluştur | false |

### Örnek Kullanım Senaryoları

#### 🎯 Temel Web Uygulaması Taraması
```bash
./vulscan https://webapp.example.com/login.php?user=admin&pass=123
```

#### 🔍 Detaylı Güvenlik Denetimi
```bash
./vulscan https://api.example.com/v1/users?id=1 \
  --verbose \
  --threads 15 \
  --timeout 20 \
  --output security_audit.json \
  --report
```

#### 🏢 Kurumsal Tarama
```bash
./vulscan https://intranet.company.com/dashboard \
  --user-agent "Security-Audit-Bot/1.0" \
  --threads 8 \
  --output corporate_scan_$(date +%Y%m%d).json \
  --report
```

## 📊 Sonuç Yorumlama

### Risk Seviyeleri

| Risk | CVSS Aralığı | Öncelik | Eylem |
|------|-------------|---------|--------|
| 🔴 **CRITICAL** | 9.0 - 10.0 | Acil | 24 saat içinde düzelt |
| 🟠 **HIGH** | 7.0 - 8.9 | Yüksek | 1 hafta içinde düzelt |
| 🟡 **MEDIUM** | 4.0 - 6.9 | Orta | 1 ay içinde düzelt |
| 🟢 **LOW** | 0.1 - 3.9 | Düşük | Sonraki güncellemede |

### Rapor Formatları

#### JSON Rapor
```json
{
  "scan_info": {
    "target": "https://example.com",
    "timestamp": "2024-01-15T10:30:00Z",
    "version": "VulScan v3.0"
  },
  "summary": {
    "total_findings": 5,
    "risk_breakdown": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 1,
      "LOW": 1
    }
  },
  "findings": [...]
}
```

## 🔧 Gelişmiş Yapılandırma

### Özel Payload'lar

Kendi payload'larınızı eklemek için `main.go` dosyasındaki payload dizilerini düzenleyebilirsiniz:

```go
var customSQLPayloads = []string{
    "'; SELECT version(); --",
    "' UNION SELECT user(); --",
    // Özel payload'larınız...
}
```

### HTTP İstemci Yapılandırması

```go
// Özel TLS yapılandırması
tr := &http.Transport{
    TLSClientConfig: &tls.Config{
        InsecureSkipVerify: true,
        MinVersion:         tls.VersionTLS12,
    },
}
```

## 🛡️ Güvenlik ve Etik Kullanım

### ⚠️ Yasal Uyarı

VulScan **sadece** aşağıdaki durumlarda kullanılmalıdır:
- ✅ Kendi sistemlerinizi test etmek
- ✅ Yazılı izin alınmış penetrasyon testleri
- ✅ Güvenlik araştırmaları (sorumlu açıklama ile)
- ✅ Eğitim amaçlı kullanım (kontrollü ortamda)

### 🚫 Yasaklanan Kullanımlar
- ❌ İzinsiz sistemleri taramak
- ❌ Kötü niyetli saldırılar
- ❌ Hizmet kesintisi oluşturmak
- ❌ Veri çalmak veya zarar vermek

**Sorumluluk Reddi:** Bu araç sadece eğitim ve yasal güvenlik testleri için geliştirilmiştir. Kullanıcılar tüm yasal sorumluluğu üstlenir.

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen [CONTRIBUTING.md](CONTRIBUTING.md) dosyasını inceleyin.

### 🐛 Hata Bildirimi
- [Issues](https://github.com/ATOMGAMERAGA/VulScan/issues) bölümünden hata bildirebilirsiniz
- Detaylı açıklama ve örnek kullanım ekleyin

### 💡 Özellik Önerileri
- Yeni güvenlik açığı türleri
- Performans iyileştirmeleri
- Yeni çıktı formatları

### 🔄 Pull Request Süreci
1. Repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📋 Yol Haritası

### v3.1 (Q1 2025)
- [ ] REST API desteği
- [ ] Database injection testleri
- [ ] WebSocket güvenlik kontrolleri
- [ ] Docker container desteği

### v3.2 (Q2 2025)
- [ ] GraphQL güvenlik testleri
- [ ] Authentication bypass testleri
- [ ] Business logic flaw detection
- [ ] Mobile API testing

## 📚 Dokümantasyon

- 📖 [Wiki](https://github.com/ATOMGAMERAGA/VulScan/wiki)
- 🎓 [Kullanım Örnekleri](https://github.com/ATOMGAMERAGA/VulScan/wiki/Examples)
- 🔧 [API Referansı](https://github.com/ATOMGAMERAGA/VulScan/wiki/API-Reference)
- 🛡️ [Güvenlik Rehberi](https://github.com/ATOMGAMERAGA/VulScan/wiki/Security-Guide)

## 📞 Destek ve İletişim

- 💬 **Discussions:** [GitHub Discussions](https://github.com/ATOMGAMERAGA/VulScan/discussions)
- 📧 **Email:** atomgameraga@atomland.xyz
- 🐦 **Twitter:** [@atomgameraga](https://twitter.com/atomgameraga)
- 💼 **LinkedIn:** [@atomgameraga](https://linkedin.com/in/atomgameraga)

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasını inceleyin.

## 🙏 Teşekkürler

### 👨‍💻 Geliştirici
- **[@ATOMGAMERAGA](https://github.com/ATOMGAMERAGA)** - Proje kurucusu ve geliştirici

### 🎯 İlham Kaynakları
Bu proje aşağıdaki kaynaklar ve standartlardan yararlanarak geliştirilmiştir:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web güvenlik açıkları referansı
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Siber güvenlik çerçevesi
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/) - Yaygın güvenlik açıkları listesi
- [CVSS v3.1](https://www.first.org/cvss/) - Güvenlik açığı skorlama sistemi

---

<div align="center">

**⭐ Projeyi beğendiyseniz yıldız vermeyi unutmayın!**

Made with ❤️ for the cybersecurity community

[🏠 Ana Sayfa](https://github.com/ATOMGAMERAGA/VulScan) • 
[📖 Dokümantasyon](https://github.com/ATOMGAMERAGA/VulScan/wiki) • 
[🐛 Hata Bildir](https://github.com/ATOMGAMERAGA/VulScan/issues) • 
[💬 Tartışmalar](https://github.com/ATOMGAMERAGA/VulScan/discussions)

</div>
