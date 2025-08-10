package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type VulScan struct {
	target      string
	client      *http.Client
	findings    []Finding
	mutex       sync.Mutex
	userAgent   string
	threads     int
	timeout     time.Duration
	verbose     bool
	outputFile  string
}

type Finding struct {
	Type        string    `json:"type"`
	URL         string    `json:"url"`
	Parameter   string    `json:"parameter"`
	Payload     string    `json:"payload"`
	Response    string    `json:"response"`
	Risk        string    `json:"risk"`
	Description string    `json:"description"`
	Solution    string    `json:"solution"`
	References  []string  `json:"references"`
	CWE         string    `json:"cwe"`
	CVSS        float64   `json:"cvss"`
	Timestamp   time.Time `json:"timestamp"`
}

type Config struct {
	Target     string
	Threads    int
	Timeout    int
	Verbose    bool
	OutputFile string
	UserAgent  string
	Headers    map[string]string
}

// Genişletilmiş payload'lar
var sqlPayloads = []string{
	"'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
	"'; DROP TABLE users;--", "' UNION SELECT NULL--", "1' AND 1=1--",
	"admin'--", "' OR 'a'='a", "1' OR '1'='1' /*", "' UNION SELECT 1,2,3--",
	"' AND extractvalue(1, concat(0x7e, version(), 0x7e))--",
	"' AND (SELECT * FROM (SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
}

var xssPayloads = []string{
	"<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
	"javascript:alert('XSS')", "<svg onload=alert('XSS')>",
	"'><script>alert('XSS')</script>", "\"><script>alert('XSS')</script>",
	"<iframe src=javascript:alert('XSS')>", "<body onload=alert('XSS')>",
	"<input onfocus=alert('XSS') autofocus>", "<select onfocus=alert('XSS') autofocus>",
	"<textarea onfocus=alert('XSS') autofocus>", "<keygen onfocus=alert('XSS') autofocus>",
	"<video><source onerror=\"alert('XSS')\">", "<audio src=x onerror=alert('XSS')>",
}

var lfiPayloads = []string{
	"../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
	"....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
	"..%252f..%252f..%252fetc%252fpasswd", "php://filter/read=convert.base64-encode/resource=index.php",
	"/proc/version", "/proc/self/environ", "C:\\boot.ini", "C:\\windows\\system.ini",
}

var blindSQLPayloads = []string{
	"' AND (SELECT * FROM (SELECT SLEEP(5))x)--",
	"'; WAITFOR DELAY '0:0:5'--",
	"' AND pg_sleep(5)--",
	"' UNION SELECT SLEEP(5)--",
}

func NewVulScan(config Config) *VulScan {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	
	timeout := time.Duration(config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = "VulScan/3.0 Advanced Security Scanner"
	}

	return &VulScan{
		target:     config.Target,
		client:     client,
		findings:   make([]Finding, 0),
		threads:    config.Threads,
		timeout:    timeout,
		verbose:    config.Verbose,
		outputFile: config.OutputFile,
		userAgent:  userAgent,
	}
}

func (v *VulScan) addFinding(finding Finding) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	finding.Timestamp = time.Now()
	v.findings = append(v.findings, finding)
}

func (v *VulScan) makeRequest(method, url string, body string, headers map[string]string) (*http.Response, error) {
	var req *http.Request
	var err error

	if method == "GET" {
		req, err = http.NewRequest("GET", url, nil)
	} else {
		req, err = http.NewRequest("POST", url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", v.userAgent)
	
	// Özel header'lar ekle
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return v.client.Do(req)
}

func (v *VulScan) scanSQL(targetURL string, params map[string]string) {
	if v.verbose {
		fmt.Printf("[*] SQL Injection taraması başlatılıyor: %s\n", targetURL)
	}
	
	for param := range params {
		for _, payload := range sqlPayloads {
			testParams := make(map[string]string)
			for k, val := range params {
				testParams[k] = val
			}
			testParams[param] = payload

			getURL := targetURL + "?" + encodeParams(testParams)
			resp, err := v.makeRequest("GET", getURL, "", nil)
			if err != nil {
				continue
			}

			body, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)

			if v.detectSQLError(bodyStr) {
				cvss := v.calculateCVSS("SQL_INJECTION")
				v.addFinding(Finding{
					Type:        "SQL Injection",
					URL:         getURL,
					Parameter:   param,
					Payload:     payload,
					Response:    bodyStr[:min(300, len(bodyStr))],
					Risk:        "HIGH",
					CVSS:        cvss,
					Description: "SQL hata mesajı tespit edildi. Saldırgan bu açığı kullanarak veritabanına yetkisiz erişim sağlayabilir, veri çalabilir veya değiştirebilir.",
					CWE:         "CWE-89",
					Solution: `KAPSAMLI ÇÖZÜM ÖNERİLERİ:

🔧 HEMEN YAPILACAKLAR:
1. Parametreli sorgular (Prepared Statements) kullanın
2. Stored procedures ile veri erişimini sınırlandırın
3. Input validation ve sanitization uygulayın
4. Hata mesajlarını production'da gizleyin

💻 KOD ÖRNEKLERİ:

PHP (PDO):
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND name = ?");
$stmt->execute([$user_id, $name]);
$result = $stmt->fetchAll();

Java (PreparedStatement):
String sql = "SELECT * FROM users WHERE id = ? AND name = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setInt(1, userId);
pstmt.setString(2, userName);

Python (SQLAlchemy):
result = session.query(User).filter(User.id == user_id).first()

🛡️ GÜVENLİK KATIMLARI:
- WAF (Web Application Firewall) kullanın
- Database user'ı minimum yetkilerle çalıştırın
- SQL injection detection tools kullanın
- Düzenli güvenlik testleri yapın`,
					References: []string{
						"https://owasp.org/www-community/attacks/SQL_Injection",
						"https://cwe.mitre.org/data/definitions/89.html",
						"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
					},
				})
				if v.verbose {
					fmt.Printf("[!] SQL Injection bulundu: %s (param: %s, CVSS: %.1f)\n", targetURL, param, cvss)
				}
			}
		}
	}

	// Blind SQL Injection testi
	v.scanBlindSQL(targetURL, params)
}

func (v *VulScan) scanBlindSQL(targetURL string, params map[string]string) {
	if v.verbose {
		fmt.Printf("[*] Blind SQL Injection taraması başlatılıyor: %s\n", targetURL)
	}

	for param := range params {
		for _, payload := range blindSQLPayloads {
			testParams := make(map[string]string)
			for k, val := range params {
				testParams[k] = val
			}
			testParams[param] = payload

			getURL := targetURL + "?" + encodeParams(testParams)
			
			start := time.Now()
			resp, err := v.makeRequest("GET", getURL, "", nil)
			elapsed := time.Since(start)
			
			if err != nil {
				continue
			}
			resp.Body.Close()

			// 4 saniyeden fazla sürdüyse blind SQL injection olabilir
			if elapsed > 4*time.Second {
				cvss := v.calculateCVSS("BLIND_SQL_INJECTION")
				v.addFinding(Finding{
					Type:        "Blind SQL Injection (Time-based)",
					URL:         getURL,
					Parameter:   param,
					Payload:     payload,
					Response:    fmt.Sprintf("Response time: %.2f seconds", elapsed.Seconds()),
					Risk:        "HIGH",
					CVSS:        cvss,
					Description: "Zaman tabanlı Blind SQL Injection tespit edildi. Saldırgan veri varlığını kontrol edebilir.",
					CWE:         "CWE-89",
					Solution: `BLIND SQL INJECTION ÇÖZÜMÜ:

🚨 DERHAL UYGULANACAK:
- Parametreli sorgular kullanın
- Response time'ı normalize edin
- Rate limiting uygulayın

⏱️ TİME-BASED KORUMA:
- Query timeout'larını ayarlayın  
- Asenkron işleme geçin
- Response caching kullanın`,
					References: []string{
						"https://owasp.org/www-community/attacks/Blind_SQL_Injection",
						"https://portswigger.net/web-security/sql-injection/blind",
					},
				})
				if v.verbose {
					fmt.Printf("[!] Blind SQL Injection bulundu: %s (%.2fs delay)\n", targetURL, elapsed.Seconds())
				}
			}
		}
	}
}

func (v *VulScan) scanXSS(targetURL string, params map[string]string) {
	if v.verbose {
		fmt.Printf("[*] XSS taraması başlatılıyor: %s\n", targetURL)
	}
	
	for param := range params {
		for _, payload := range xssPayloads {
			testParams := make(map[string]string)
			for k, val := range params {
				testParams[k] = val
			}
			testParams[param] = payload

			getURL := targetURL + "?" + encodeParams(testParams)
			resp, err := v.makeRequest("GET", getURL, "", nil)
			if err != nil {
				continue
			}

			body, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)

			if strings.Contains(bodyStr, payload) || v.detectXSSContext(bodyStr, payload) {
				cvss := v.calculateCVSS("XSS")
				v.addFinding(Finding{
					Type:        "Cross-Site Scripting (XSS)",
					URL:         getURL,
					Parameter:   param,
					Payload:     payload,
					Response:    bodyStr[:min(300, len(bodyStr))],
					Risk:        "MEDIUM",
					CVSS:        cvss,
					Description: "XSS açığı tespit edildi. Saldırgan kullanıcının tarayıcısında zararlı kod çalıştırabilir.",
					CWE:         "CWE-79",
					Solution: `KAPSAMLI XSS KORUMA STRATEJİSİ:

🔒 INPUT/OUTPUT SANİTİZASYONU:
1. Tüm kullanıcı girdilerini encode edin
2. Context-aware output encoding yapın
3. Whitelist yaklaşımı benimseyin

💻 UYGULAMA ÖRNEKLERİ:

PHP:
echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');

JavaScript:
const sanitize = (str) => {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
};

React:
// Otomatik escaping - güvenli
<div>{userInput}</div>
// Tehlikeli - kaçının
<div dangerouslySetInnerHTML={{__html: userInput}} />

🛡️ CSP (Content Security Policy):
Content-Security-Policy: default-src 'self'; 
    script-src 'self' 'unsafe-inline'; 
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;

🍪 COOKIE GÜVENLİĞİ:
- HttpOnly flag ekleyin
- Secure flag kullanın (HTTPS için)
- SameSite=Strict ayarlayın`,
					References: []string{
						"https://owasp.org/www-community/attacks/xss/",
						"https://cwe.mitre.org/data/definitions/79.html",
						"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
					},
				})
				if v.verbose {
					fmt.Printf("[!] XSS bulundu: %s (param: %s, CVSS: %.1f)\n", targetURL, param, cvss)
				}
			}
		}
	}
}

func (v *VulScan) scanLFI(targetURL string, params map[string]string) {
	if v.verbose {
		fmt.Printf("[*] Directory Traversal/LFI taraması başlatılıyor: %s\n", targetURL)
	}
	
	for param := range params {
		for _, payload := range lfiPayloads {
			testParams := make(map[string]string)
			for k, val := range params {
				testParams[k] = val
			}
			testParams[param] = payload

			getURL := targetURL + "?" + encodeParams(testParams)
			resp, err := v.makeRequest("GET", getURL, "", nil)
			if err != nil {
				continue
			}

			body, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)

			if v.detectLFI(bodyStr) {
				cvss := v.calculateCVSS("LFI")
				v.addFinding(Finding{
					Type:        "Directory Traversal/Local File Inclusion",
					URL:         getURL,
					Parameter:   param,
					Payload:     payload,
					Response:    bodyStr[:min(300, len(bodyStr))],
					Risk:        "HIGH",
					CVSS:        cvss,
					Description: "Dosya sistem erişim açığı tespit edildi. Saldırgan kritik sistem dosyalarını okuyabilir.",
					CWE:         "CWE-22",
					Solution: `DOSYA ERİŞİM GÜVENLİĞİ:

🚫 DERHAL ENGELLEYIN:
1. Relative path karakterlerini (.., ./) filtreleyin
2. Whitelist yaklaşımı benimseyin
3. Dosya yolu doğrulaması yapın

🔒 GÜVENLİ UYGULAMA:

PHP:
$allowedFiles = [
    'about' => '/safe/path/about.html',
    'contact' => '/safe/path/contact.html'
];

$file = $_GET['page'] ?? '';
if (isset($allowedFiles[$file])) {
    include $allowedFiles[$file];
} else {
    http_response_code(404);
    die('Sayfa bulunamadı');
}

Python (Flask):
import os
from flask import abort, send_file

def safe_file_serve(filename):
    # Güvenli dizin
    safe_dir = '/var/www/safe/'
    # Path traversal koruması  
    safe_path = os.path.realpath(os.path.join(safe_dir, filename))
    
    if not safe_path.startswith(safe_dir):
        abort(403)
    
    if not os.path.exists(safe_path):
        abort(404)
        
    return send_file(safe_path)

🛡️ SİSTEM SEVİYESİ KORUMA:
- Chroot jail kullanın
- SELinux/AppArmor profillerini aktifleştirin
- Dosya izinlerini minimum seviyede tutun
- Logging ve monitoring ekleyin`,
					References: []string{
						"https://owasp.org/www-community/attacks/Path_Traversal",
						"https://cwe.mitre.org/data/definitions/22.html",
						"https://portswigger.net/web-security/file-path-traversal",
					},
				})
				if v.verbose {
					fmt.Printf("[!] Directory Traversal bulundu: %s (param: %s, CVSS: %.1f)\n", targetURL, param, cvss)
				}
			}
		}
	}
}

func (v *VulScan) scanHeaders(targetURL string) {
	if v.verbose {
		fmt.Printf("[*] HTTP Header güvenlik taraması başlatılıyor: %s\n", targetURL)
	}
	
	resp, err := v.makeRequest("GET", targetURL, "", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	securityHeaders := map[string]HeaderInfo{
		"X-Frame-Options": {
			Description: "Clickjacking saldırılarını önler",
			Solution: "X-Frame-Options: DENY",
			CVSS: 4.3,
		},
		"X-XSS-Protection": {
			Description: "Tarayıcı XSS korumasını etkinleştirir",
			Solution: "X-XSS-Protection: 1; mode=block",
			CVSS: 3.1,
		},
		"X-Content-Type-Options": {
			Description: "MIME type sniffing saldırılarını önler",
			Solution: "X-Content-Type-Options: nosniff",
			CVSS: 2.6,
		},
		"Strict-Transport-Security": {
			Description: "HTTPS bağlantısını zorunlu kılar",
			Solution: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
			CVSS: 5.4,
		},
		"Content-Security-Policy": {
			Description: "XSS ve data injection saldırılarını önler",
			Solution: "Content-Security-Policy: default-src 'self'",
			CVSS: 6.1,
		},
		"Referrer-Policy": {
			Description: "Referrer bilgisinin paylaşımını kontrol eder",
			Solution: "Referrer-Policy: strict-origin-when-cross-origin",
			CVSS: 2.3,
		},
		"Permissions-Policy": {
			Description: "Tarayıcı API erişimlerini kontrol eder",
			Solution: "Permissions-Policy: geolocation=(), microphone=(), camera=()",
			CVSS: 3.7,
		},
	}

	for header, info := range securityHeaders {
		if resp.Header.Get(header) == "" {
			v.addFinding(Finding{
				Type:        "Missing Security Header",
				URL:         targetURL,
				Parameter:   header,
				Risk:        v.getRiskLevel(info.CVSS),
				CVSS:        info.CVSS,
				Description: fmt.Sprintf("Eksik güvenlik header: %s - %s", header, info.Description),
				CWE:         "CWE-693",
				Solution: fmt.Sprintf(`GÜVENLİK HEADER YAPΙLANDIRMASI:

🔧 %s HEADER'I:
%s

📋 UYGULAMA ÖRNEKLERİ:

Apache (.htaccess):
Header always set %s "%s"

Nginx:
add_header %s "%s" always;

Express.js:
app.use((req, res, next) => {
    res.setHeader('%s', '%s');
    next();
});

PHP:
header('%s: %s');`, header, info.Solution, header, getDefaultHeaderValue(header), header, getDefaultHeaderValue(header), header, getDefaultHeaderValue(header), header, getDefaultHeaderValue(header)),
				References: []string{
					"https://owasp.org/www-project-secure-headers/",
					"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/" + header,
				},
			})
		}
	}

	// Server/Technology disclosure
	v.scanTechDisclosure(resp, targetURL)
}

func (v *VulScan) scanTechDisclosure(resp *http.Response, targetURL string) {
	disclosureHeaders := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"}
	
	for _, header := range disclosureHeaders {
		if value := resp.Header.Get(header); value != "" {
			v.addFinding(Finding{
				Type:        "Information Disclosure",
				URL:         targetURL,
				Parameter:   header,
				Response:    value,
				Risk:        "LOW",
				CVSS:        2.1,
				Description: fmt.Sprintf("%s header'ı teknoloji bilgisi açığa çıkarıyor: %s", header, value),
				CWE:         "CWE-200",
				Solution: `BİLGİ SIZINTISI ÖNLEME:

🔒 HEADER'LARI GİZLEYİN:

Apache:
ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By
Header unset X-Generator

Nginx:
server_tokens off;
more_clear_headers 'Server';
more_clear_headers 'X-Powered-By';

PHP:
expose_php = Off

Express.js:
app.disable('x-powered-by');

IIS web.config:
<system.web>
    <httpRuntime enableVersionHeader="false" />
</system.web>
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <remove name="X-Powered-By" />
        </customHeaders>
    </httpProtocol>
</system.webServer>`,
				References: []string{
					"https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
				},
			})
		}
	}
}

func (v *VulScan) scanSSL(targetURL string) {
	if !strings.HasPrefix(targetURL, "https://") {
		return
	}

	if v.verbose {
		fmt.Printf("[*] SSL/TLS güvenlik taraması başlatılıyor: %s\n", targetURL)
	}

	// TLS version check için özel client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10, // Test için tüm versiyonları kabul et
		},
	}
	
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		// Eski TLS versiyonu kontrolü
		if resp.TLS.Version < tls.VersionTLS12 {
			v.addFinding(Finding{
				Type:        "Weak TLS Version",
				URL:         targetURL,
				Risk:        "MEDIUM",
				CVSS:        5.8,
				Description: fmt.Sprintf("Zayıf TLS versiyonu kullanılıyor: %s", getTLSVersion(resp.TLS.Version)),
				CWE:         "CWE-326",
				Solution: `TLS GÜVENLİK YAPΙLANDIRMASI:

🔒 TLS 1.2+ ZORUNLU KILIN:

Apache:
SSLProtocol -all +TLSv1.2 +TLSv1.3

Nginx:
ssl_protocols TLSv1.2 TLSv1.3;

Cloudflare:
Minimum TLS Version: 1.2

Node.js:
const options = {
    secureProtocol: 'TLSv1_2_method',
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:...'
};`,
				References: []string{
					"https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning",
					"https://wiki.mozilla.org/Security/Server_Side_TLS",
				},
			})
		}

		// Weak cipher kontrolü
		if v.isWeakCipher(resp.TLS.CipherSuite) {
			v.addFinding(Finding{
				Type:        "Weak SSL Cipher",
				URL:         targetURL,
				Risk:        "MEDIUM",
				CVSS:        4.8,
				Description: "Zayıf SSL cipher suite kullanılıyor",
				CWE:         "CWE-327",
				Solution: `GÜVENLİ CİPHER SUITE'LERİ:

🔐 ÖNERİLEN YAPΙLANDIRMA:

Apache:
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

Nginx:
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;`,
				References: []string{
					"https://wiki.mozilla.org/Security/Server_Side_TLS",
				},
			})
		}
	}
}

func (v *VulScan) scanCSRF(targetURL string) {
	if v.verbose {
		fmt.Printf("[*] CSRF koruması taraması başlatılıyor: %s\n", targetURL)
	}
	
	resp, err := v.makeRequest("GET", targetURL, "", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	formRegex := regexp.MustCompile(`(?i)<form[^>]*>`)
	if !formRegex.MatchString(bodyStr) {
		return
	}

	csrfPatterns := []string{
		`(?i)name=["\']?(_token|csrf_token|authenticity_token)["\']?`,
		`(?i)name=["\']?_csrf["\']?`,
		`(?i)<input[^>]*hidden[^>]*token`,
		`(?i)X-CSRF-TOKEN`,
	}

	hasCSRFToken := false
	for _, pattern := range csrfPatterns {
		matched, _ := regexp.MatchString(pattern, bodyStr)
		if matched {
			hasCSRFToken = true
			break
		}
	}

	if !hasCSRFToken {
		v.addFinding(Finding{
			Type:        "Cross-Site Request Forgery (CSRF)",
			URL:         targetURL,
			Parameter:   "CSRF Token",
			Risk:        "MEDIUM",
			CVSS:        6.8,
			Description: "CSRF koruması eksik. Saldırgan kullanıcı adına yetkisiz işlem yapabilir.",
			CWE:         "CWE-352",
			Solution: `CSRF KORUMA STRATEJİSİ:

🛡️ TOKEN TABANLI KORUMA:

PHP:
session_start();
// Token üret
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Form'da token
<input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

// Token doğrula
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
    die('CSRF token hatası');
}

Express.js:
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

app.get('/form', (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
});

React:
// Meta tag'den token al
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

fetch('/api/data', {
    method: 'POST',
    headers: {
        'X-CSRF-TOKEN': csrfToken,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
});

🍪 SAMESITE COOKIE KORUMA:
Set-Cookie: sessionid=abc123; SameSite=Strict; Secure; HttpOnly

🔍 REFERRER KONTROLÜ:
if (parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) !== $_SERVER['HTTP_HOST']) {
    die('Geçersiz referrer');
}`,
			References: []string{
				"https://owasp.org/www-community/attacks/csrf",
				"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
			},
		})
	}
}

func (v *VulScan) scanCookies(targetURL string) {
	if v.verbose {
		fmt.Printf("[*] Cookie güvenlik taraması başlatılıyor: %s\n", targetURL)
	}
	
	resp, err := v.makeRequest("GET", targetURL, "", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}

	for _, cookie := range cookies {
		issues := []string{}
		
		if !cookie.Secure && strings.HasPrefix(targetURL, "https://") {
			issues = append(issues, "Secure flag eksik")
		}
		
		if !cookie.HttpOnly {
			issues = append(issues, "HttpOnly flag eksik")
		}
		
		if cookie.SameSite == 0 {
			issues = append(issues, "SameSite attribute eksik")
		}

		if len(issues) > 0 {
			v.addFinding(Finding{
				Type:        "Insecure Cookie Configuration",
				URL:         targetURL,
				Parameter:   cookie.Name,
				Response:    fmt.Sprintf("Cookie: %s=%s", cookie.Name, cookie.Value[:min(50, len(cookie.Value))]),
				Risk:        "MEDIUM",
				CVSS:        4.2,
				Description: fmt.Sprintf("Cookie güvenlik sorunları: %s", strings.Join(issues, ", ")),
				CWE:         "CWE-614",
				Solution: `COOKIE GÜVENLİK YAPΙLANDIRMASI:

🍪 GÜVENLİ COOKIE AYARLARI:

PHP:
setcookie('session_id', $value, [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => 'example.com', 
    'secure' => true,        // HTTPS için
    'httponly' => true,      // XSS koruması
    'samesite' => 'Strict'   // CSRF koruması
]);

Express.js:
app.use(session({
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 3600000
    }
}));

ASP.NET:
<system.web>
    <httpCookies requireSSL="true" httpOnlyCookies="true" sameSite="Strict" />
</system.web>

Django:
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

🛡️ COOKIE POLİTİKASI:
- Hassas bilgileri cookie'de saklamayın
- Kısa süre geçerlilik ayarlayın
- Domain ve Path'i sınırlandırın`,
				References: []string{
					"https://owasp.org/www-community/controls/SecureFlag",
					"https://owasp.org/www-community/HttpOnly",
					"https://web.dev/samesite-cookies-explained/",
				},
			})
		}
	}
}

func (v *VulScan) scanOpenRedirect(targetURL string, params map[string]string) {
	if v.verbose {
		fmt.Printf("[*] Open Redirect taraması başlatılıyor: %s\n", targetURL)
	}

	redirectPayloads := []string{
		"http://evil.com",
		"https://attacker.com",
		"//evil.com",
		"javascript:alert('redirect')",
		"data:text/html,<script>alert('redirect')</script>",
	}

	for param := range params {
		for _, payload := range redirectPayloads {
			testParams := make(map[string]string)
			for k, val := range params {
				testParams[k] = val
			}
			testParams[param] = payload

			getURL := targetURL + "?" + encodeParams(testParams)
			
			// Redirect'leri takip etme
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Timeout: 10 * time.Second,
			}

			resp, err := client.Get(getURL)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if strings.Contains(location, payload) || strings.Contains(location, "evil.com") {
					v.addFinding(Finding{
						Type:        "Open Redirect",
						URL:         getURL,
						Parameter:   param,
						Payload:     payload,
						Response:    fmt.Sprintf("Location: %s", location),
						Risk:        "MEDIUM",
						CVSS:        5.4,
						Description: "Açık yönlendirme açığı tespit edildi. Saldırgan kullanıcıları zararlı sitelere yönlendirebilir.",
						CWE:         "CWE-601",
						Solution: `OPEN REDIRECT KORUNMASI:

🔒 URL DOĞRULAMA:

PHP:
function safe_redirect($url) {
    // Whitelist yaklaşımı
    $allowed_domains = ['example.com', 'subdomain.example.com'];
    $parsed = parse_url($url);
    
    if (!in_array($parsed['host'], $allowed_domains)) {
        header('Location: /');
        exit();
    }
    
    header('Location: ' . $url);
    exit();
}

Python (Django):
from django.shortcuts import redirect
from django.urls import is_valid_path
from urllib.parse import urlparse

def safe_redirect_view(request):
    next_url = request.GET.get('next', '/')
    
    # Relative URL kontrolü
    if next_url.startswith('/') and not next_url.startswith('//'):
        if is_valid_path(next_url):
            return redirect(next_url)
    
    # Varsayılan güvenli yönlendirme
    return redirect('/')

JavaScript:
function validateRedirect(url) {
    try {
        const urlObj = new URL(url, window.location.origin);
        const allowedHosts = ['example.com', 'subdomain.example.com'];
        
        return allowedHosts.includes(urlObj.hostname);
    } catch {
        return false;
    }
}`,
						References: []string{
							"https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
							"https://cwe.mitre.org/data/definitions/601.html",
						},
					})
					if v.verbose {
						fmt.Printf("[!] Open Redirect bulundu: %s -> %s\n", getURL, location)
					}
				}
			}
		}
	}
}

// Yardımcı fonksiyonlar
func (v *VulScan) calculateCVSS(vulnType string) float64 {
	cvssScores := map[string]float64{
		"SQL_INJECTION":       9.1,
		"BLIND_SQL_INJECTION": 8.5,
		"XSS":                 6.1,
		"LFI":                 8.7,
		"CSRF":                6.8,
		"OPEN_REDIRECT":       5.4,
	}
	
	if score, exists := cvssScores[vulnType]; exists {
		return score
	}
	return 0.0
}

func (v *VulScan) getRiskLevel(cvss float64) string {
	if cvss >= 9.0 {
		return "CRITICAL"
	} else if cvss >= 7.0 {
		return "HIGH"
	} else if cvss >= 4.0 {
		return "MEDIUM"
	}
	return "LOW"
}

func (v *VulScan) detectXSSContext(body, payload string) bool {
	// Daha gelişmiş XSS context detection
	contexts := []string{
		`<script[^>]*>.*` + regexp.QuoteMeta(payload),
		`on\w+\s*=\s*["'].*` + regexp.QuoteMeta(payload),
		`javascript:.*` + regexp.QuoteMeta(payload),
	}
	
	for _, context := range contexts {
		matched, _ := regexp.MatchString("(?i)"+context, body)
		if matched {
			return true
		}
	}
	return false
}

func getTLSVersion(version uint16) string {
	versions := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1", 
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	
	if v, exists := versions[version]; exists {
		return v
	}
	return "Bilinmeyen"
}

func (v *VulScan) isWeakCipher(suite uint16) bool {
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}
	
	for _, weak := range weakCiphers {
		if suite == weak {
			return true
		}
	}
	return false
}

type HeaderInfo struct {
	Description string
	Solution    string
	CVSS        float64
}

func getDefaultHeaderValue(header string) string {
	defaults := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
	}
	return defaults[header]
}

func (v *VulScan) detectSQLError(body string) bool {
	sqlErrors := []string{
		"mysql_fetch_array", "ORA-[0-9]+", "Microsoft.*ODBC.*SQL",
		"PostgreSQL.*ERROR", "Warning.*mysql_", "valid MySQL result",
		"MySQLSyntaxErrorException", "sqlite3.OperationalError", "SQLiteException",
		"SQL syntax.*MySQL", "Warning.*sqlite_", "SQLite error",
		"sqlite3.DatabaseError", "Unclosed quotation mark after", "Microsoft Access Driver",
		"OLE DB.*error", "Microsoft JET Database", "ADODB.Field.*error",
	}

	for _, pattern := range sqlErrors {
		matched, _ := regexp.MatchString("(?i)"+pattern, body)
		if matched {
			return true
		}
	}
	return false
}

func (v *VulScan) detectLFI(body string) bool {
	patterns := []string{
		"root:.*:0:0:", "\\[drivers\\]", "\\[boot loader\\]", "daemon:.*:1:1:",
		"microsoft windows", "\\[operating systems\\]", "\\[fonts\\]",
		"\\[extensions\\]", "\\[MCI Extensions\\]", "ECHO is on\\.",
		"Volume.* Serial Number", "Directory of C:", "boot\\.ini",
		"config\\.sys", "autoexec\\.bat",
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString("(?i)"+pattern, body)
		if matched {
			return true
		}
	}
	return false
}

func encodeParams(params map[string]string) string {
	values := url.Values{}
	for key, value := range params {
		values.Add(key, value)
	}
	return values.Encode()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (v *VulScan) printResults() {
	fmt.Println("\n" + strings.Repeat("═", 100))
	fmt.Println("🛡️  VULSCAN v3.0 - KAPSAMLI GÜVENLİK TARAMA RAPORU")
	fmt.Println(strings.Repeat("═", 100))
	
	if len(v.findings) == 0 {
		fmt.Println("✅ Tarama tamamlandı - Açık güvenlik açığı tespit edilmedi!")
		fmt.Println("🎉 Tebrikler! Hedef sistem güvenlik testlerinden başarıyla geçti.")
		return
	}

	riskCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	totalCVSS := 0.0
	
	for i, finding := range v.findings {
		riskCounts[finding.Risk]++
		totalCVSS += finding.CVSS
		
		fmt.Printf("\n🚨 GÜVENLIK AÇIĞI #%d\n", i+1)
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════════════════════════\n")
		
		// Risk rengi ile göster
		riskEmoji := map[string]string{
			"CRITICAL": "🔴",
			"HIGH":     "🟠", 
			"MEDIUM":   "🟡",
			"LOW":      "🟢",
		}
		
		fmt.Printf("📍 TİP: %s\n", finding.Type)
		fmt.Printf("⚠️  RİSK SEVİYESİ: %s %s\n", riskEmoji[finding.Risk], finding.Risk)
		fmt.Printf("📊 CVSS SKORU: %.1f/10\n", finding.CVSS)
		fmt.Printf("🕒 TESPİT ZAMANI: %s\n", finding.Timestamp.Format("2006-01-02 15:04:05"))
		
		if finding.CWE != "" {
			fmt.Printf("🔍 CWE: %s\n", finding.CWE)
		}
		
		fmt.Printf("🌐 HEDEF URL: %s\n", finding.URL)
		
		if finding.Parameter != "" {
			fmt.Printf("📝 PARAMETRE: %s\n", finding.Parameter)
		}
		if finding.Payload != "" {
			fmt.Printf("💥 PAYLOAD: %s\n", finding.Payload)
		}
		if finding.Response != "" {
			fmt.Printf("📥 YANIT ÖRNEĞİ: %s...\n", finding.Response)
		}
		
		fmt.Printf("\n📋 AÇIKLAMA:\n%s\n", finding.Description)
		fmt.Printf("\n🛠️  ÇÖZÜM ÖNERİLERİ:\n%s\n", finding.Solution)
		
		if len(finding.References) > 0 {
			fmt.Printf("\n📚 REFERANSLAR:\n")
			for _, ref := range finding.References {
				fmt.Printf("   🔗 %s\n", ref)
			}
		}
		
		fmt.Println(strings.Repeat("─", 100))
	}

	// Detaylı özet rapor
	avgCVSS := totalCVSS / float64(len(v.findings))
	
	fmt.Printf("\n📊 DETAYLI ÖZET RAPOR\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("🔴 Kritik Risk:     %d açık\n", riskCounts["CRITICAL"]) 
	fmt.Printf("🟠 Yüksek Risk:     %d açık\n", riskCounts["HIGH"])
	fmt.Printf("🟡 Orta Risk:       %d açık\n", riskCounts["MEDIUM"])
	fmt.Printf("🟢 Düşük Risk:      %d açık\n", riskCounts["LOW"])
	fmt.Printf("📈 Toplam Açık:     %d\n", len(v.findings))
	fmt.Printf("📊 Ortalama CVSS:   %.1f/10\n", avgCVSS)
	
	// Risk değerlendirmesi ve öneriler
	fmt.Printf("\n💡 RİSK DEĞERLENDİRMESİ VE ÖNCELİKLER\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════════════════════════\n")
	
	if riskCounts["CRITICAL"] > 0 {
		fmt.Printf("🚨 ACİL DURUM: %d kritik açık derhal kapatılmalı!\n", riskCounts["CRITICAL"])
		fmt.Printf("⏰ Maksimum 24 saat içinde düzeltilmesi öneriliyor.\n")
	}
	if riskCounts["HIGH"] > 0 {
		fmt.Printf("⚠️  YÜKSEK ÖNCELİK: %d yüksek riskli açık 1 hafta içinde kapatılmalı.\n", riskCounts["HIGH"])
	}
	if riskCounts["MEDIUM"] > 0 {
		fmt.Printf("🔶 ORTA ÖNCELİK: %d orta riskli açık 1 ay içinde düzeltilmeli.\n", riskCounts["MEDIUM"])
	}
	if riskCounts["LOW"] > 0 {
		fmt.Printf("🔷 DÜŞÜK ÖNCELİK: %d düşük riskli bulgu gelecek güncelleme döneminde düzeltilebilir.\n", riskCounts["LOW"])
	}

	// Genel güvenlik önerileri
	fmt.Printf("\n🛡️  GENEL GÜVENLİK ÖNERİLERİ\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("1. 🔄 Düzenli güvenlik taramaları yapın (ayda 1 kez)\n")
	fmt.Printf("2. 🔐 Güçlü kimlik doğrulama mekanizmaları kullanın\n") 
	fmt.Printf("3. 🛡️  WAF (Web Application Firewall) kurulumunu değerlendirin\n")
	fmt.Printf("4. 📊 Güvenlik loglarını izleyin ve analiz edin\n")
	fmt.Printf("5. 🎓 Geliştirici ekibine güvenlik eğitimleri verin\n")
	fmt.Printf("6. 🔍 Penetrasyon testlerini profesyonel firmalardan alın\n")
	
	fmt.Printf("\n✨ VulScan v3.0 ile tarama tamamlandı!\n")
}

func (v *VulScan) generateJSONReport() error {
	if v.outputFile == "" {
		return nil
	}
	
	report := map[string]interface{}{
		"scan_info": map[string]interface{}{
			"target":    v.target,
			"timestamp": time.Now(),
			"version":   "VulScan v3.0",
		},
		"summary": map[string]interface{}{
			"total_findings": len(v.findings),
			"risk_breakdown": v.getRiskBreakdown(),
			"avg_cvss":       v.getAverageCVSS(),
		},
		"findings": v.findings,
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(v.outputFile, jsonData, 0644)
}

func (v *VulScan) getRiskBreakdown() map[string]int {
	breakdown := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, finding := range v.findings {
		breakdown[finding.Risk]++
	}
	return breakdown
}

func (v *VulScan) getAverageCVSS() float64 {
	if len(v.findings) == 0 {
		return 0.0
	}
	
	total := 0.0
	for _, finding := range v.findings {
		total += finding.CVSS
	}
	return total / float64(len(v.findings))
}

func (v *VulScan) generateHTMLReport() error {
	htmlContent := `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulScan v3.0 - Güvenlik Raporu</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { 
            background: rgba(255,255,255,0.95);
            padding: 30px;
            border-radius: 20px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        .stats { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }
        .finding { 
            background: white;
            margin: 20px 0;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
        }
        .finding-header {
            padding: 20px;
            color: white;
            font-weight: bold;
        }
        .critical { background: linear-gradient(45deg, #ff6b6b, #ee5a52); }
        .high { background: linear-gradient(45deg, #ffa726, #ff9800); }
        .medium { background: linear-gradient(45deg, #ffee58, #fdd835); color: #333; }
        .low { background: linear-gradient(45deg, #66bb6a, #4caf50); }
        .finding-body { padding: 25px; }
        .solution { 
            background: #f8f9fa;
            padding: 20px;
            margin: 15px 0;
            border-radius: 10px;
            border-left: 4px solid #007bff;
        }
        .code { 
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            margin: 10px 0;
            overflow-x: auto;
        }
        .references { margin-top: 15px; }
        .references a { 
            display: inline-block;
            background: #e3f2fd;
            color: #1976d2;
            padding: 5px 10px;
            margin: 5px;
            border-radius: 15px;
            text-decoration: none;
            font-size: 12px;
        }
        h1 { color: #2c3e50; margin-bottom: 10px; }
        h2 { color: #34495e; margin-bottom: 15px; }
        .meta { color: #7f8c8d; margin-bottom: 15px; }
        .badge { 
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 10px;
        }
        .cvss-badge { background: #17a2b8; color: white; }
        .cwe-badge { background: #6c757d; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VulScan v3.0 - Gelişmiş Güvenlik Raporu</h1>
            <div class="meta">
                <strong>Hedef:</strong> ` + v.target + `<br>
                <strong>Tarama Tarihi:</strong> ` + time.Now().Format("2006-01-02 15:04:05") + `<br>
                <strong>Toplam Bulgu:</strong> ` + strconv.Itoa(len(v.findings)) + `
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card critical">
                <h3>` + strconv.Itoa(v.getRiskBreakdown()["CRITICAL"]) + `</h3>
                <p>Kritik Risk</p>
            </div>
            <div class="stat-card high">
                <h3>` + strconv.Itoa(v.getRiskBreakdown()["HIGH"]) + `</h3>
                <p>Yüksek Risk</p>
            </div>
            <div class="stat-card medium">
                <h3>` + strconv.Itoa(v.getRiskBreakdown()["MEDIUM"]) + `</h3>
                <p>Orta Risk</p>
            </div>
            <div class="stat-card low">
                <h3>` + strconv.Itoa(v.getRiskBreakdown()["LOW"]) + `</h3>
                <p>Düşük Risk</p>
            </div>
        </div>`

	for i, finding := range v.findings {
		riskClass := strings.ToLower(finding.Risk)
		htmlContent += fmt.Sprintf(`
        <div class="finding">
            <div class="finding-header %s">
                <h2>🚨 Bulgu #%d: %s</h2>
                <div>
                    <span class="badge cvss-badge">CVSS %.1f</span>
                    <span class="badge cwe-badge">%s</span>
                </div>
            </div>
            <div class="finding-body">
                <p><strong>URL:</strong> %s</p>
                <p><strong>Parametre:</strong> %s</p>
                <p><strong>Açıklama:</strong> %s</p>
                
                <div class="solution">
                    <h4>🛠️ Çözüm Önerileri:</h4>
                    <div class="code">%s</div>
                </div>
                
                <div class="references">
                    <strong>📚 Referanslar:</strong><br>`,
			riskClass, i+1, finding.Type, finding.CVSS, finding.CWE,
			finding.URL, finding.Parameter, finding.Description, finding.Solution)

		for _, ref := range finding.References {
			htmlContent += fmt.Sprintf(`<a href="%s" target="_blank">%s</a>`, ref, ref)
		}

		htmlContent += `
                </div>
            </div>
        </div>`
	}

	htmlContent += `
    </div>
</body>
</html>`

	return ioutil.WriteFile("vulscan_rapor_v3.html", []byte(htmlContent), 0644)
}

func main() {
	fmt.Println(`
 __      __     _ _____                 
 \ \    / /    | / ____|                
  \ \  / /   _ | | (___   ___ __ _ _ __  
   \ \/ / | | || \___ \ / __/ _ | '_ \ 
    \  /| |_| || ____) | (_| (_| | | | |
     \/ \__,_||_|_____/ \___\__,_|_| |_|
                                        
    🛡️  VulScan v3.0 - Gelişmiş Web Güvenlik Tarayıcısı
    ⚡ Yeni: CVSS skorlama, JSON çıktı, SSL/TLS kontrolleri
    `)

	if len(os.Args) < 2 {
		fmt.Println("📋 KULLANIM:")
		fmt.Println("  ./vulscan <hedef_url> [seçenekler]")
		fmt.Println("\n🎯 ÖRNEKLER:")
		fmt.Println("  ./vulscan http://example.com/page.php?id=1")
		fmt.Println("  ./vulscan http://example.com --verbose --threads 10")
		fmt.Println("  ./vulscan http://example.com --output report.json --timeout 15")
		fmt.Println("\n⚙️ SEÇENEKLER:")
		fmt.Println("  --verbose, -v     : Detaylı çıktı")
		fmt.Println("  --threads, -t     : Thread sayısı (varsayılan: 5)")
		fmt.Println("  --timeout         : İstek zaman aşımı (saniye, varsayılan: 10)")
		fmt.Println("  --output, -o      : JSON çıktı dosyası")
		fmt.Println("  --user-agent, -u  : Özel User-Agent")
		fmt.Println("  --report          : HTML rapor oluştur")
		os.Exit(1)
	}

	// Komut satırı argümanlarını parse et
	config := Config{
		Target:  os.Args[1],
		Threads: 5,
		Timeout: 10,
		Verbose: false,
	}

	// Seçenekleri işle
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "--verbose", "-v":
			config.Verbose = true
		case "--threads", "-t":
			if i+1 < len(os.Args) {
				if threads, err := strconv.Atoi(os.Args[i+1]); err == nil {
					config.Threads = threads
					i++
				}
			}
		case "--timeout":
			if i+1 < len(os.Args) {
				if timeout, err := strconv.Atoi(os.Args[i+1]); err == nil {
					config.Timeout = timeout
					i++
				}
			}
		case "--output", "-o":
			if i+1 < len(os.Args) {
				config.OutputFile = os.Args[i+1]
				i++
			}
		case "--user-agent", "-u":
			if i+1 < len(os.Args) {
				config.UserAgent = os.Args[i+1]
				i++
			}
		case "--report":
			// HTML rapor flag'i - generateHTMLReport() çağırılacak
		}
	}

	// URL'yi parse et ve doğrula
	u, err := url.Parse(config.Target)
	if err != nil {
		fmt.Printf("❌ Geçersiz URL: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🎯 Hedef URL: %s\n", config.Target)
	fmt.Printf("⚙️  Thread Sayısı: %d\n", config.Threads)
	fmt.Printf("⏱️  Timeout: %d saniye\n", config.Timeout)
	if config.Verbose {
		fmt.Printf("📢 Verbose mod: Aktif\n")
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 JSON çıktı: %s\n", config.OutputFile)
	}
	fmt.Println("\n🚀 Gelişmiş güvenlik taraması başlatılıyor...")
	fmt.Println(strings.Repeat("─", 80))

	scanner := NewVulScan(config)

	// URL'den parametreleri çıkar
	params := make(map[string]string)
	for key, values := range u.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	// Varsayılan test parametreleri ekle
	if len(params) == 0 {
		params["id"] = "1"
		params["page"] = "index"
		params["search"] = "test"
		params["file"] = "page"
		params["url"] = "https://example.com"
		params["redirect"] = "/dashboard"
	}

	baseURL := strings.Split(config.Target, "?")[0]
	var wg sync.WaitGroup

	// Paralel tarama işlemleri
	scanTasks := []func(){
		func() {
			defer wg.Done()
			scanner.scanSQL(baseURL, params)
		},
		func() {
			defer wg.Done()
			scanner.scanXSS(baseURL, params)
		},
		func() {
			defer wg.Done()
			scanner.scanLFI(baseURL, params)
		},
		func() {
			defer wg.Done()
			scanner.scanHeaders(baseURL)
		},
		func() {
			defer wg.Done()
			scanner.scanCSRF(baseURL)
		},
		func() {
			defer wg.Done()
			scanner.scanCookies(baseURL)
		},
		func() {
			defer wg.Done()
			scanner.scanSSL(config.Target)
		},
		func() {
			defer wg.Done()
			scanner.scanOpenRedirect(baseURL, params)
		},
	}

	// Thread havuzu ile taramaları çalıştır
	semaphore := make(chan struct{}, config.Threads)
	
	for _, task := range scanTasks {
		wg.Add(1)
		go func(t func()) {
			semaphore <- struct{}{}
			t()
			<-semaphore
		}(task)
	}

	wg.Wait()

	// Sonuçları göster
	scanner.printResults()

	// JSON raporu oluştur (eğer belirtilmişse)
	if config.OutputFile != "" {
		if err := scanner.generateJSONReport(); err != nil {
			fmt.Printf("❌ JSON raporu oluşturulamadı: %v\n", err)
		} else {
			fmt.Printf("✅ JSON raporu oluşturuldu: %s\n", config.OutputFile)
		}
	}

	// HTML raporu oluştur (eğer --report belirtilmişse)
	for _, arg := range os.Args {
		if arg == "--report" {
			if err := scanner.generateHTMLReport(); err != nil {
				fmt.Printf("❌ HTML raporu oluşturulamadı: %v\n", err)
			} else {
				fmt.Printf("✅ HTML raporu oluşturuldu: vulscan_rapor_v3.html\n")
			}
			break
		}
	}

	// Son özet
	riskCount := scanner.getRiskBreakdown()
	totalFindings := len(scanner.findings)
	
	fmt.Printf("\n🎊 TARAMA TAMAMLANDI!\n")
	fmt.Printf("══════════════════════════════════════════════════════════════════════════════════════════════════\n")
	
	if totalFindings > 0 {
		fmt.Printf("📊 %d güvenlik açığı tespit edildi\n", totalFindings)
		fmt.Printf("⚡ Ortalama CVSS skoru: %.1f/10\n", scanner.getAverageCVSS())
		
		if riskCount["CRITICAL"] > 0 || riskCount["HIGH"] > 0 {
			fmt.Printf("\n🚨 ACİL EYLEM GEREKLİ: Yüksek/Kritik riskli açıkları derhal kapatın!\n")
		}
		
		fmt.Printf("\n💡 Sonraki adımlar:\n")
		fmt.Printf("   1. 🔴 Kritik ve yüksek riskli açıkları önceliklendirin\n")
		fmt.Printf("   2. 🛠️  Çözüm önerilerini uygulayın\n") 
		fmt.Printf("   3. 🔄 Düzeltmelerden sonra yeniden tarayın\n")
		fmt.Printf("   4. 🎓 Geliştirici ekibini güvenlik konularında eğitin\n")
	} else {
		fmt.Printf("🎉 Mükemmel! Hiçbir güvenlik açığı bulunamadı.\n")
		fmt.Printf("✨ Sisteminiz temel güvenlik testlerini başarıyla geçti.\n")
		fmt.Printf("\n💡 Güvenlik önerileri:\n")
		fmt.Printf("   • 🔄 Düzenli güvenlik taramaları yapın\n")
		fmt.Printf("   • 🛡️  WAF kullanmayı değerlendirin\n")
		fmt.Printf("   • 📊 Güvenlik loglarını izleyin\n")
		fmt.Printf("   • 🎯 Daha kapsamlı penetrasyon testi yaptırın\n")
	}

	fmt.Printf("\n🔗 Daha fazla bilgi için: https://owasp.org/www-project-top-ten/\n")
	fmt.Printf("⭐ VulScan v3.0 - Made with ❤️  for cybersecurity\n")
}
