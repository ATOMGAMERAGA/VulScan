# 🤝 Contributing to VulScan

Öncelikle VulScan projesine katkıda bulunmak istediğiniz için teşekkür ederiz! Bu rehber, katkı sürecini kolaylaştırmak için hazırlanmıştır.

## 📋 İçindekiler

- [Davranış Kuralları](#-davranış-kuralları)
- [Nasıl Katkıda Bulunabilirim?](#-nasıl-katkıda-bulunabilirim)
- [Geliştirme Ortamı Kurulumu](#️-geliştirme-ortamı-kurulumu)
- [Pull Request Süreci](#-pull-request-süreci)
- [Kod Standartları](#-kod-standartları)
- [Test Etme](#-test-etme)
- [Dokümantasyon](#-dokümantasyon)

## 📜 Davranış Kuralları

Bu projede **herkes için güvenli ve kapsayıcı** bir ortam sağlamayı hedefliyoruz. Lütfen aşağıdaki kuralları takip edin:

### ✅ Yapılması Gerekenler
- Saygılı ve profesyonel dil kullanın
- Farklı görüşlere açık olun
- Yapıcı geri bildirim verin
- Yeni gelenlere yardımcı olun
- Güvenlik bulgularını sorumlu bir şekilde bildirin

### ❌ Yapılmaması Gerekenler
- Saldırgan, aşağılayıcı veya taciz edici davranış
- Kişisel bilgilerin paylaşımı
- Spam veya konu dışı içerik
- Kötü niyetli kod paylaşımı
- Yasal olmayan aktivitelere teşvik

## 🎯 Nasıl Katkıda Bulunabilirim?

### 🐛 Hata Bildirimi

Bir hata bulduğunuzda:

1. **Mevcut issue'ları kontrol edin** - Daha önce bildirilmiş olabilir
2. **Detaylı açıklama yazın**:
   ```
   **Hata Açıklaması:**
   Kısa ve açık hata tanımı
   
   **Beklenen Davranış:**
   Ne olmasını bekliyordunuz?
   
   **Gerçek Davranış:**
   Ne oldu?
   
   **Çoğaltma Adımları:**
   1. ...
   2. ...
   3. ...
   
   **Ortam:**
   - İşletim Sistemi: [örn. Ubuntu 22.04]
   - Go Version: [örn. 1.21.0]
   - VulScan Version: [örn. v4.1.0]
   
   **Ek Bilgiler:**
   Ekran görüntüleri, loglar vb.
   ```

### 💡 Özellik Önerisi

Yeni bir özellik önermek için:

1. **Özelliğin amacını açıklayın**
2. **Kullanım senaryosunu tanımlayın**
3. **Teknik detayları paylaşın** (varsa)
4. **Benzer araçlardaki implementasyonları** araştırın

### 🔧 Kod Katkısı

Aşağıdaki alanlarda katkıda bulunabilirsiniz:

#### 🎯 Yüksek Öncelikli Alanlar
- **Yeni güvenlik açığı türleri** (XXE, Deserialization, etc.)
- **Performans optimizasyonları**
- **Test coverage artırımı**
- **Dokümantasyon iyileştirmeleri**

#### 🔍 Orta Öncelikli Alanlar
- **Yeni çıktı formatları** (XML, CSV, etc.)
- **Gelişmiş raporlama özellikleri**
- **UI/UX iyileştirmeleri**
- **Multilingual support**

#### 💻 Düşük Öncelikli Alanlar
- **Code refactoring**
- **Minor bug fixes**
- **Cosmetic improvements**

## 🛠️ Geliştirme Ortamı Kurulumu

### Gereksinimler
- **Go 1.19+**
- **Git**
- **Code editor** (VS Code, GoLand, etc.)

### Kurulum Adımları

```bash
# 1. Repository'yi fork edin ve klonlayın
git clone https://github.com/ATOMGAMERAGA/VulScan.git
cd VulScan

# 2. Upstream remote'u ekleyin
git remote add upstream https://github.com/ATOMGAMERAGA/VulScan.git

# 3. Go modüllerini yükleyin
go mod download

# 4. Development branch oluşturun
git checkout -b feature/your-feature-name

# 5. Test edin
go run main.go http://testphp.vulnweb.com/listproducts.php?cat=1
```

### Önerilen Geliştirme Araçları

```bash
# Go linting
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/tools/cmd/goimports@latest

# Security scanning
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Dependency check
go install github.com/sonatypecommunity/nancy@latest
```

## 🔄 Pull Request Süreci

### 1. Branch Oluşturma

```bash
# Feature branch oluşturun
git checkout -b feature/new-vulnerability-check
git checkout -b fix/sql-injection-bug
git checkout -b docs/update-readme
```

### 2. Geliştirme

- **Küçük, atomik commit'ler** yapın
- **Açıklayıcı commit mesajları** yazın:
  ```
  feat: add XXE vulnerability detection
  
  - Implement XML External Entity detection logic
  - Add comprehensive payload list
  - Include test cases for various scenarios
  - Update documentation with examples
  
  Closes #123
  ```

### 3. Test Etme

```bash
# Unit testleri çalıştırın
go test ./...

# Security scanning
gosec ./...

# Code formatting
goimports -w .
go fmt ./...

# Static analysis
staticcheck ./...
```

### 4. Pull Request Oluşturma

**Pull Request Template:**

```markdown
## 📋 Değişiklik Özeti

Kısa açıklama...

## 🎯 Değişiklik Türü

- [ ] 🐛 Bug fix (breaking olmayan değişiklik)
- [ ] ✨ New feature (breaking olmayan özellik ekleme)
- [ ] 💥 Breaking change (mevcut fonksiyonaliteyi etkileyen değişiklik)
- [ ] 📚 Documentation update

## 🧪 Test Edildi

- [ ] Unit testler geçiyor
- [ ] Integration testler geçiyor
- [ ] Manual test yapıldı

**Test ortamı:**
- İşletim Sistemi: 
- Go Version: 
- Test hedefleri: 

## 📸 Ekran Görüntüleri (varsa)

## ✅ Kontrol Listesi

- [ ] Kod review'den geçti
- [ ] Tests eklendi/güncellendi
- [ ] Dokümantasyon güncellendi
- [ ] CHANGELOG.md güncellendi
```

## 📝 Kod Standartları

### Go Best Practices

```go
// ✅ İyi örnek
func (v *VulScan) detectSQLInjection(url string, params map[string]string) []Finding {
    var findings []Finding
    
    for param, value := range params {
        for _, payload := range sqlPayloads {
            // Test implementasyonu
            if finding := v.testSQLPayload(url, param, payload); finding != nil {
                findings = append(findings, *finding)
            }
        }
    }
    
    return findings
}

// ❌ Kötü örnek
func detect(u string, p map[string]string) []Finding {
    f := []Finding{}
    // Açıklayıcı olmayan değişken isimleri
    // Eksik error handling
    return f
}
```

### Naming Conventions

```go
// Package names: lowercase, single word
package scanner

// Functions: camelCase, verb + noun
func scanSQLInjection()
func detectXSSVulnerability()

// Types: PascalCase
type VulnerabilityFinding struct {}

// Constants: camelCase or SCREAMING_SNAKE_CASE
const maxRetries = 3
const DEFAULT_TIMEOUT = 10
```

### Error Handling

```go
// ✅ Proper error handling
func (v *VulScan) makeRequest(url string) (*http.Response, error) {
    resp, err := v.client.Get(url)
    if err != nil {
        return nil, fmt.Errorf("HTTP request failed: %w", err)
    }
    
    if resp.StatusCode >= 400 {
        return nil, fmt.Errorf("HTTP %d error", resp.StatusCode)
    }
    
    return resp, nil
}
```

### Logging

```go
// Verbose logging kullanın
if v.verbose {
    fmt.Printf("[*] SQL Injection taraması başlatılıyor: %s\n", targetURL)
}

// Error logging
if err != nil {
    fmt.Printf("[ERROR] Request failed: %v\n", err)
    return
}
```

## 🧪 Test Etme

### Unit Tests

```go
func TestSQLInjectionDetection(t *testing.T) {
    tests := []struct {
        name     string
        response string
        expected bool
    }{
        {
            name:     "MySQL error detected",
            response: "mysql_fetch_array(): supplied argument is not a valid MySQL result",
            expected: true,
        },
        {
            name:     "No SQL error",
            response: "Welcome to our website",
            expected: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            scanner := &VulScan{}
            result := scanner.detectSQLError(tt.response)
            if result != tt.expected {
                t.Errorf("detectSQLError() = %v, want %v", result, tt.expected)
            }
        })
    }
}
```

### Integration Tests

```bash
# Test lab ortamları
./vulscan http://testphp.vulnweb.com/listproducts.php?cat=1
./vulscan http://demo.testfire.net/login.jsp
```

### Benchmark Tests

```go
func BenchmarkSQLInjectionScan(b *testing.B) {
    scanner := NewVulScan(Config{})
    params := map[string]string{"id": "1"}
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        scanner.scanSQL("http://example.com", params)
    }
}
```

## 📚 Dokümantasyon

### Code Documentation

```go
// DetectSQLInjection SQL injection açıklarını tespit eder
// 
// Bu fonksiyon verilen URL ve parametrelerde SQL injection açıkları
// arar. Error-based ve time-based detection yöntemlerini kullanır.
//
// Parameters:
//   - targetURL: Taranacak URL
//   - params: Test edilecek parametreler
//
// Returns:
//   - []Finding: Bulunan güvenlik açıkları listesi
func (v *VulScan) DetectSQLInjection(targetURL string, params map[string]string) []Finding {
    // Implementation
}
```

### README Updates

Yeni özellik eklediğinizde README.md'yi güncelleyin:

```markdown
### 🆕 v4.0.0 Updates
- ✨ XXE vulnerability detection
- 🚀 Performance improvements (40% faster scanning)
- 📊 Enhanced HTML reports with charts
- 🔧 New command line options: --config, --exclude
```

## 🏷️ Release Process

### Version Numbering

[Semantic Versioning](https://semver.org/) kullanıyoruz:
- **MAJOR**: Breaking changes
- **MINOR**: Backwards compatible features
- **PATCH**: Backwards compatible bug fixes

### Changelog Format

```markdown
## [4.0.0] - 2024-12-19

### Added ✨
- XXE vulnerability detection
- New HTML report template
- Configuration file support

### Changed 🔄
- Improved SQL injection detection accuracy
- Updated default payloads

### Fixed 🐛
- False positive in XSS detection
- Memory leak in concurrent scanning

### Deprecated ⚠️
- Old JSON format (will be removed in v4.0)

### Removed 🗑️
- Legacy HTTP client implementation

### Security 🔒
- Fixed potential command injection in report generation
```

## 🎉 Recognition

Katkıda bulunanlar aşağıdaki şekillerde tanınır:

### Contributors Section
- README.md'de contributor listesi
- Release notes'larda katkı bildirimleri

### Commit Recognition
- Git history'de katkılarınız kalıcı olarak kayıtlı kalır
- GitHub profile'ınızda contribution graph'te görünür

### Special Thanks
- Major contributions için özel teşekkür bölümü
- Security researchers için özel tanınma

## 📞 İletişim

Sorularınız veya yardıma ihtiyacınız varsa:

- 💬 [GitHub Discussions](https://github.com/ATOMGAMERAGA/VulScan/discussions)
- 📧 Email: atomgameraga@atomland.xyz
- 🐦 Twitter: [@atomgameraga](https://twitter.com/atomgameraga)

## 📄 Lisans

Bu projeye katkıda bulunarak, katkılarınızın MIT lisansı altında lisanslanmasını kabul etmiş olursunuz.

---

**Katkınız için tekrar teşekkür ederiz! 🙏**

Birlikte daha güvenli bir internet oluşturalım! 🛡️✨
