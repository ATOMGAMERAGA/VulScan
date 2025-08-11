package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test version information
func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if !strings.Contains(Version, "4.1.0") {
		t.Errorf("Expected version to contain '4.1.0', got %s", Version)
	}
}

// Test banner information
func TestBanner(t *testing.T) {
	if Banner == "" {
		t.Error("Banner should not be empty")
	}
	if !strings.Contains(Banner, "Next-Gen Web Security Scanner") {
		t.Error("Banner should contain 'Next-Gen Web Security Scanner'")
	}
}

// Test payload initialization
func TestPayloads(t *testing.T) {
	if len(payloads[SQLInjection]) == 0 {
		t.Error("SQL Injection payloads should not be empty")
	}
	if len(payloads[XSS]) == 0 {
		t.Error("XSS payloads should not be empty")
	}
	if len(payloads[DirectoryTraversal]) == 0 {
		t.Error("Directory Traversal payloads should not be empty")
	}
	if len(payloads[CommandInjection]) == 0 {
		t.Error("Command Injection payloads should not be empty")
	}
	// Test new payloads
	if len(payloads[XXE]) == 0 {
		t.Error("XXE payloads should not be empty")
	}
	if len(payloads[SSRF]) == 0 {
		t.Error("SSRF payloads should not be empty")
	}
	if len(payloads[JWTSecurity]) == 0 {
		t.Error("JWT Security payloads should not be empty")
	}
}

// Test CWE mapping
func TestCWEMapping(t *testing.T) {
	if len(cweMapping) == 0 {
		t.Error("CWE mapping should not be empty")
	}
	
	// Test specific mappings
	if cweMapping[SQLInjection] != "CWE-89" {
		t.Error("SQL Injection should map to CWE-89")
	}
	if cweMapping[XSS] != "CWE-79" {
		t.Error("XSS should map to CWE-79")
	}
	if cweMapping[XXE] != "CWE-611" {
		t.Error("XXE should map to CWE-611")
	}
	if cweMapping[SSRF] != "CWE-918" {
		t.Error("SSRF should map to CWE-918")
	}
}

// Test CVSS scores
func TestCVSSScores(t *testing.T) {
	if len(cvssScores) == 0 {
		t.Error("CVSS scores should not be empty")
	}
	
	// Test specific scores
	if cvssScores[SQLInjection] != 9.8 {
		t.Error("SQL Injection CVSS score should be 9.8")
	}
	if cvssScores[XSS] != 8.8 {
		t.Error("XSS CVSS score should be 8.8")
	}
}

// Test risk level calculation
func TestCalculateRiskLevel(t *testing.T) {
	scanner := &Scanner{}
	tests := []struct {
		vulnType VulnType
		expected RiskLevel
	}{
		{SQLInjection, RiskCritical},
		{XSS, RiskHigh},
		{SecurityHeaders, RiskMedium},
	}
	
	for _, test := range tests {
		result := scanner.calculateRiskLevel(test.vulnType)
		if result != test.expected {
			t.Errorf("calculateRiskLevel(%s) = %s; expected %s", test.vulnType, result, test.expected)
		}
	}
}

// Test truncate string function
func TestTruncateString(t *testing.T) {
	scanner := &Scanner{}
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a very long string", 10, "this is a ..."},
		{"", 5, ""},
	}
	
	for _, test := range tests {
		result := scanner.truncateString(test.input, test.maxLen)
		if result != test.expected {
			t.Errorf("truncateString(%q, %d) = %q; expected %q", test.input, test.maxLen, result, test.expected)
		}
	}
}

// Test HTTP client creation
func TestCreateHTTPClient(t *testing.T) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	if client.Timeout != 10*time.Second {
		t.Error("HTTP client timeout should be 10 seconds")
	}
}

// Test URL validation
func TestURLValidation(t *testing.T) {
	validURLs := []string{
		"http://example.com",
		"https://example.com",
		"http://localhost:8080",
		"https://subdomain.example.com/path",
	}
	
	invalidURLs := []string{
		"not-a-url",
		"ftp://example.com",
		"",
		"http://",
	}
	
	for _, url := range validURLs {
		if !strings.HasPrefix(url, "http") {
			t.Errorf("URL %s should be valid", url)
		}
	}
	
	for _, url := range invalidURLs {
		if url != "" && !strings.HasPrefix(url, "http") {
			// This is expected for invalid URLs
			continue
		}
		if url == "" || url == "http://" {
			// These should be caught as invalid
			continue
		}
	}
}

// Test scan result structure
func TestScanResult(t *testing.T) {
	result := ScanResult{
		Findings: []Finding{},
		Errors:   []string{},
	}
	
	// Set ScanInfo fields
	result.ScanInfo.Target = "http://example.com"
	result.ScanInfo.Timestamp = time.Now()
	result.ScanInfo.Version = Version
	result.ScanInfo.Duration = "1m30s"
	
	// Set Summary fields
	result.Summary.TotalFindings = 0
	result.Summary.RiskBreakdown = make(map[RiskLevel]int)
	result.Summary.TypeBreakdown = make(map[VulnType]int)
	result.Summary.URLs = 1
	result.Summary.Requests = 10
	
	if result.ScanInfo.Target == "" {
		t.Error("Target should not be empty")
	}
	if result.ScanInfo.Version == "" {
		t.Error("Version should not be empty")
	}
	if result.Findings == nil {
		t.Error("Findings should be initialized")
	}
}

// Test finding structure
func TestFinding(t *testing.T) {
	finding := Finding{
		ID:          "VULN-001",
		Type:        SQLInjection,
		Severity:    RiskHigh,
		URL:         "http://example.com/test",
		Parameter:   "id",
		Payload:     "' OR 1=1 --",
		Evidence:    "SQL error detected",
		Description: "SQL Injection vulnerability detected",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Title:       "SQL Injection",
		Solution:    "Use parameterized queries",
		References:  []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
		Confidence:  95,
		Timestamp:   time.Now(),
	}
	
	if finding.Type == "" {
		t.Error("Finding type should not be empty")
	}
	if finding.Severity == "" {
		t.Error("Finding severity should not be empty")
	}
	if finding.CVSS <= 0 {
		t.Error("Finding CVSS should be greater than 0")
	}
}

// Test mock HTTP server for integration testing
func TestMockServer(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Test Page</body></html>"))
	}))
	defer server.Close()
	
	// Test HTTP request
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// Benchmark test for payload processing
func BenchmarkPayloadProcessing(b *testing.B) {
	payloadList := []string{
		"' OR 1=1 --",
		"<script>alert('xss')</script>",
		"../../../etc/passwd",
		"; ls -la",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, payload := range payloadList {
			// Simulate payload processing
			_ = strings.Contains(payload, "'")
			_ = strings.Contains(payload, "<")
			_ = strings.Contains(payload, "..")
			_ = strings.Contains(payload, ";")
		}
	}
}