# 🛡️ VulScan v4.1.0 - Advanced Web Security Scanner with AI-Powered Detection

[![Go Version](https://img.shields.io/badge/Go-1.19+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Security-First-red?style=for-the-badge&logo=security)](https://github.com/ATOMGAMERAGA/VulScan)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)](https://github.com/ATOMGAMERAGA/VulScan)

> **⚡ Gelişmiş, hızlı ve kapsamlı web güvenlik açığı tarayıcısı**

VulScan v4.1.0, modern web uygulamalarında yaygın güvenlik açıklarını tespit eden, CVSS skorlaması yapan ve detaylı raporlar üreten açık kaynak güvenlik tarama aracıdır. Yeni sürümde AI destekli tespit algoritmaları, genişletilmiş güvenlik açığı kütüphanesi ve gelişmiş keşif özellikleri bulunmaktadır.

## 🌟 Özellikler

### 🔍 Kapsamlı Güvenlik Taraması

#### 🎯 Temel Güvenlik Açıkları
- **SQL Injection** - Klasik, Blind ve Time-based SQL Injection tespiti
- **Cross-Site Scripting (XSS)** - Reflected, Stored ve DOM tabanlı XSS
- **Directory Traversal/LFI** - Yerel ve uzak dosya dahil etme açıkları
- **Remote File Inclusion (RFI)** - Uzak dosya dahil etme açıkları
- **Cross-Site Request Forgery (CSRF)** - Token eksikliği ve bypass teknikleri
- **Open Redirect** - Açık yönlendirme ve phishing açıkları
- **HTTP Security Headers** - 15+ güvenlik başlığı analizi
- **SSL/TLS Configuration** - TLS 1.3 desteği ve cipher suite analizi
- **Cookie Security** - SameSite, Secure, HttpOnly kontrolleri

#### 🆕 Gelişmiş Güvenlik Açıkları (v4.0.0)
- **Authentication Bypass** - Session ve JWT güvenlik testleri
- **API Security** - REST ve GraphQL endpoint güvenliği
- **Command Injection** - OS komut enjeksiyon testleri
- **XML External Entity (XXE)** - XML parser güvenlik açıkları
- **Server-Side Request Forgery (SSRF)** - Sunucu taraflı istek sahteciliği
- **Insecure Direct Object References (IDOR)** - Yetkisiz nesne erişimi

### 📊 Gelişmiş Raporlama & AI Destekli Analiz
- **CVSS v3.1 Skorlaması** - Endüstri standardı risk değerlendirmesi
- **Multi-format Export** - JSON, HTML, PDF, XML çıktı desteği
- **Interactive Dashboard** - Web tabanlı görsel raporlar
- **CWE/OWASP Mapping** - Güvenlik açığı kategorilendirmesi
- **Executive Summary** - Yönetici düzeyi risk raporları
- **Remediation Guide** - Kod örnekleri ile detaylı çözümler
- **Trend Analysis** - Zamansal güvenlik açığı analizi
- **🆕 AI-Powered Pattern Recognition** - Gelişmiş tespit algoritmaları
- **🆕 Enhanced Payload Library** - Genişletilmiş saldırı vektörleri
- **🆕 Modern Web Tech Support** - GraphQL, JWT, API güvenliği

### ⚡ Performans & Kullanılabilirlik
- **Paralel Tarama** - Çoklu thread desteği (1-100 thread)
- **Akıllı Rate Limiting** - Ayarlanabilir istek hızı kontrolü
- **Verbose Logging** - Detaylı tarama süreci takibi
- **Flexible Configuration** - YAML konfigürasyon dosyası desteği
- **Custom Payload Support** - Harici payload dosyaları yükleme
- **Proxy Support** - HTTP/HTTPS proxy desteği
- **Custom Headers** - Özel HTTP başlıkları ekleme
- **Context-aware Scanning** - Zaman aşımı ve iptal mekanizmaları
- **Error Handling** - Kapsamlı hata yönetimi ve raporlama

## 🚀 Hızlı Başlangıç

### Gereksinimler
- **Go 1.19+** (Önerilen: Go 1.21+) - [golang.org](https://golang.org/)
- **İnternet bağlantısı** - Payload güncellemeleri ve CVE veritabanı için
- **Minimum RAM:** 512MB (Büyük taramalar için 2GB önerilir)

### 📦 Kurulum

> **📋 Detaylı kurulum talimatları ve farklı işletim sistemleri için [Wiki - Hızlı Başlangıç](https://github.com/ATOMGAMERAGA/VulScan/wiki#-h%C4%B1zl%C4%B1-ba%C5%9Flang%C4%B1%C3%A7) sayfasını ziyaret edin.**

#### 🪟 Windows Otomatik Kurulum (Önerilen)

**Seçenek 1: PowerShell Tek Komut Kurulum** ⚡
```powershell
# Ana kurulum yöntemi (Önerilen)
irm https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main/install.ps1 | iex
```

**Seçenek 2: Batch Installer (Yedek Kurulum)** 🛠️
```powershell
# PowerShell ile batch installer'ı indir ve çalıştır
iwr https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main/install.bat -OutFile install.bat && .\install.bat

# Veya CMD kullanarak
powershell -c "iwr https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main/install.bat -OutFile install.bat" && install.bat
```

> **💡 Hangi kurulum yöntemini seçmeliyim?**
> - **PowerShell kurulumu** daha hızlı ve otomatiktir (Seçenek 1)
> - **Batch kurulumu** daha fazla kontrole ve seçeneğe sahiptir (Seçenek 2)
> - Her iki yöntem de tam otomatik kurulum yapacaktır

#### 🐧 Linux Otomatik Kurulum
```bash
# Otomatik kurulum scripti
bash <(curl -sSL https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main/safe-install.sh)
```

#### 🍎 macOS Otomatik Kurulum
```bash
# Otomatik kurulum scripti
bash <(curl -sSL https://raw.githubusercontent.com/ATOMGAMERAGA/VulScan/main/main/safe-install.sh)
```

#### Manual Kurulum (Tüm Platformlar)

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

#### Platform Özel Kurulumlar

| Platform | Otomatik Kurulum | Manuel Kurulum | Wiki Linki |
|----------|------------------|----------------|------------|
| 🪟 **Windows** | PowerShell + Batch | Native binary | [Windows Kurulumu](https://github.com/ATOMGAMERAGA/VulScan/wiki#windows-kurulumu) |
| 🐧 **Linux** | Script + Package Manager | Native binary | [Linux Kurulumu](https://github.com/ATOMGAMERAGA/VulScan/wiki#linux-kurulumu) |
| 🍎 **macOS** | Script + Homebrew | Native binary | [macOS Kurulumu](https://github.com/ATOMGAMERAGA/VulScan/wiki#macos-kurulumu) |
| 🐳 **Docker** | - | Container deployment | [Docker Kurulumu](https://github.com/ATOMGAMERAGA/VulScan/wiki#docker-kurulumu) |

### ⚡ Hızlı Test

```bash
# Temel tarama testi (yeni özelliklerle)
vulscan http://example.com/page.php?id=1

# Detaylı tarama (geliştirilmiş performans)
vulscan http://example.com --verbose --threads 10

# Çoklu format rapor oluşturma
vulscan http://example.com --output report.json --report

# API endpoint taraması
vulscan -v http://api.example.com/v1/users

# GraphQL endpoint taraması
vulscan -v http://example.com/graphql

# Yardım ve sürüm bilgisi
vulscan --help
vulscan --version
```

> **💡 İpucu:** İlk kez kullanıyorsanız `--help` parametresi ile tüm seçenekleri görebilirsiniz.

## 📖 Kullanım Kılavuzu

### Komut Satırı Seçenekleri

| Parametre | Kısa | Açıklama | Varsayılan |
|-----------|------|----------|------------|
| `--verbose` | `-v` | Detaylı çıktı modu | false |
| `--threads` | `-t` | Paralel thread sayısı | 5 |
| `--timeout` | | İstek zaman aşımı (saniye) | 10 |
| `--output` | `-o` | JSON çıktı dosyası | - |
| `--user-agent` | `-u` | Özel User-Agent | VulScan/4.1.0 |
| `--report` | | HTML rapor oluştur | false |
| `--format` | `-f` | Rapor formatı (html,pdf,json) | json |
| `--proxy` | | HTTP/HTTPS proxy | - |
| `--headers` | | Özel HTTP başlıkları | - |
| `--config` | | YAML konfigürasyon dosyası | - |
| `--rate-limit` | | İstek/saniye limiti | 10 |
| `--version` | | Sürüm bilgisi göster | - |
| `--help` | `-h` | Yardım mesajını göster | - |

### Örnek Kullanım Senaryoları

#### 🎯 Temel Web Uygulaması Taraması
```bash
vulscan https://webapp.example.com/login.php?user=admin&pass=123
```

#### 🔍 Detaylı Güvenlik Denetimi
```bash
vulscan https://api.example.com/v1/users?id=1 \
  --verbose \
  --threads 15 \
  --timeout 20 \
  --output security_audit.json \
  --report
```

#### 🏢 Kurumsal Tarama
```bash
vulscan https://intranet.company.com/dashboard \
  --user-agent "Security-Audit-Bot/1.0" \
  --threads 8 \
  --rate-limit 5 \
  --proxy http://proxy.company.com:8080 \
  --headers "Authorization:Bearer token123,X-API-Key:key456" \
  --config corporate-config.yaml \
  --output corporate_scan_$(date +%Y%m%d).json \
  --report
```

#### 🔧 Payload Dosyaları ile Tarama
```bash
# Özel payload dosyaları kullanarak tarama
vulscan http://target.com/app?id=1 \
  --config custom-payloads.yaml \
  --verbose \
  --output detailed_scan.json
```

#### 🌐 Proxy ve Header Desteği
```bash
# Proxy üzerinden özel headerlar ile tarama
vulscan https://api.example.com/v1/users \
  --proxy socks5://127.0.0.1:9050 \
  --headers "X-Forwarded-For:127.0.0.1,Accept:application/json" \
  --rate-limit 3
```

> **📚 Daha fazla örnek için:** [Wiki - Kullanım Örnekleri](https://github.com/ATOMGAMERAGA/VulScan/wiki/Examples) sayfasını inceleyin.

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
    "timestamp": "2025-08-10T14:30:00Z",
    "version": "VulScan v4.1.0",
    "duration": "2m15s",
    "options": {
      "threads": 10,
      "timeout": 10,
      "rate_limit": 10
    }
  },
  "summary": {
    "total_findings": 5,
    "urls_tested": 1,
    "total_requests": 127,
    "risk_breakdown": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 1,
      "LOW": 1
    },
    "type_breakdown": {
      "SQL_INJECTION": 2,
      "XSS": 1,
      "SECURITY_HEADERS": 2
    }
  },
  "findings": [
    {
      "id": "sqli_id_1691234567",
      "type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "cvss": 9.8,
      "cwe": "CWE-89",
      "title": "SQL Injection Vulnerability",
      "description": "SQL injection vulnerability detected in parameter 'id'",
      "url": "https://example.com/page.php?id=' OR '1'='1",
      "parameter": "id",
      "payload": "' OR '1'='1",
      "evidence": "mysql_fetch_array",
      "solution": "Use parameterized queries or prepared statements",
      "confidence": 90,
      "timestamp": "2025-08-10T14:30:15Z"
    }
  ],
  "errors": []
}
```

> **📋 Rapor formatları hakkında detaylı bilgi:** [Wiki - Rapor Analizi](https://github.com/ATOMGAMERAGA/VulScan/wiki/Report-Analysis)

## 🔧 Gelişmiş Yapılandırma

### 📝 YAML Konfigürasyon Dosyası

VulScan, kapsamlı özelleştirme için YAML konfigürasyon dosyalarını destekler:

```yaml
# config.yaml
scan:
  threads: 10
  timeout: 15
  user_agent: "CustomScanner/1.0"
  rate_limit: 5

payloads:
  sql_injection: "payloads/custom_sql.txt"
  xss: "payloads/custom_xss.txt"
  directory_traversal: "payloads/custom_lfi.txt"
  command_injection: "payloads/custom_cmd.txt"

output:
  verbose: true
  format: "json"
  report: true
```

### 📋 Özel Payload Dosyaları

Kendi test payload'larınızı oluşturabilirsiniz:

```bash
# payloads/custom_sql.txt
' OR '1'='1
'; DROP TABLE users; --
' UNION SELECT username, password FROM users--
```

### Özel Payload'lar (Kod İçinde)

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
    MaxIdleConns:       100,
    IdleConnTimeout:    30 * time.Second,
    DisableCompression: false,
}

// Proxy desteği
if options.Proxy != "" {
    proxyURL, _ := url.Parse(options.Proxy)
    tr.Proxy = http.ProxyURL(proxyURL)
}
```

### 🎯 Exit Code Anlamları

VulScan çıkış kodları ile tarama sonuçlarını belirtir:

| Exit Code | Açıklama |
|-----------|----------|
| `0` | Temiz tarama, güvenlik açığı bulunamadı |
| `1` | Düşük/Orta risk güvenlik açıkları bulundu |
| `2` | Kritik/Yüksek risk güvenlik açıkları bulundu |

> **⚙️ Gelişmiş yapılandırma rehberi:** [Wiki - Yapılandırma](https://github.com/ATOMGAMERAGA/VulScan/wiki/Configuration)

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

> **📖 Etik kullanım rehberi:** [Wiki - Güvenlik ve Etik](https://github.com/ATOMGAMERAGA/VulScan/wiki/Security-Ethics)

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

### v4.0 (Q4 2024) ✅ TAMAMLANDI
- [x] REST API desteği
- [x] Database injection testleri
- [x] WebSocket güvenlik kontrolleri
- [x] Docker container desteği

### v3.2 (Q3 2025)
- [ ] REST API desteği genişletilmesi
- [ ] Advanced Database injection testleri
- [ ] WebSocket güvenlik kontrolleri
- [ ] Kubernetes security scanning

### v4.0 (Q4 2025)
- [ ] GraphQL güvenlik testleri
- [ ] Authentication bypass testleri
- [ ] Business logic flaw detection
- [ ] Mobile API testing
- [ ] AI-powered vulnerability detection
- [ ] Cloud security scanning (AWS, Azure, GCP)

## 📚 Dokümantasyon

- 📖 [Wiki Ana Sayfa](https://github.com/ATOMGAMERAGA/VulScan/wiki)
- 🚀 [Hızlı Başlangıç](https://github.com/ATOMGAMERAGA/VulScan/wiki#-h%C4%B1zl%C4%B1-ba%C5%9Flang%C4%B1%C3%A7)
- 🎓 [Kullanım Örnekleri](https://github.com/ATOMGAMERAGA/VulScan/wiki/Examples)
- 🔧 [API Referansı](https://github.com/ATOMGAMERAGA/VulScan/wiki/API-Reference)
- 🛡️ [Güvenlik Rehberi](https://github.com/ATOMGAMERAGA/VulScan/wiki/Security-Guide)
- ⚙️ [Yapılandırma](https://github.com/ATOMGAMERAGA/VulScan/wiki/Configuration)
- 📊 [Rapor Analizi](https://github.com/ATOMGAMERAGA/VulScan/wiki/Report-Analysis)

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
[📖 Wiki](https://github.com/ATOMGAMERAGA/VulScan/wiki) • 
[🚀 Hızlı Başlangıç](https://github.com/ATOMGAMERAGA/VulScan/wiki#-h%C4%B1zl%C4%B1-ba%C5%9Flang%C4%B1%C3%A7) • 
[🐛 Hata Bildir](https://github.com/ATOMGAMERAGA/VulScan/issues) • 
[💬 Tartışmalar](https://github.com/ATOMGAMERAGA/VulScan/discussions)

</div>
