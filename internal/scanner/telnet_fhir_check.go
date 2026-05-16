package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// ── TELNET ───────────────────────────────────────────────────────────────────

type TelnetResult struct {
	Open        bool
	Banner      string
	PromptFound bool   // reached a login prompt
	NoPassword  bool   // got a shell without credentials
	DeviceHint  string // what kind of device from banner
}

// CheckTelnet connects and checks if telnet requires authentication
func CheckTelnet(ip string, port int) TelnetResult {
	result := TelnetResult{}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 3*time.Second)
	if err != nil {
		return result
	}
	defer conn.Close()
	result.Open = true
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read initial banner — telnet servers send it immediately
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n == 0 {
		return result
	}

	// Strip telnet IAC negotiation bytes (0xff sequences) for clean text
	banner := stripTelnetIAC(buf[:n])
	result.Banner = strings.TrimSpace(banner)
	result.DeviceHint = inferDeviceFromBanner(result.Banner)

	bannerLower := strings.ToLower(result.Banner)

	// Check if we already got a shell prompt without credentials
	shellPrompts := []string{"#", "$", ">", "~#", "~$"}
	for _, p := range shellPrompts {
		if strings.HasSuffix(strings.TrimSpace(bannerLower), p) {
			result.NoPassword = true
			result.PromptFound = true
			return result
		}
	}

	// Check if there's a login prompt
	loginKeywords := []string{"login:", "username:", "user:", "password:", "enter password"}
	for _, kw := range loginKeywords {
		if strings.Contains(bannerLower, kw) {
			result.PromptFound = true
			break
		}
	}

	// Try sending just a newline — some devices give a shell immediately
	conn.Write([]byte("\r\n"))
	time.Sleep(500 * time.Millisecond)
	n2, _ := conn.Read(buf)
	if n2 > 0 {
		response := strings.ToLower(strings.TrimSpace(stripTelnetIAC(buf[:n2])))
		for _, p := range shellPrompts {
			if strings.HasSuffix(response, p) {
				result.NoPassword = true
				break
			}
		}
	}

	return result
}

func stripTelnetIAC(data []byte) string {
	var out []byte
	for i := 0; i < len(data); i++ {
		if data[i] == 0xff && i+2 < len(data) {
			i += 2 // skip IAC + command + option
			continue
		}
		if data[i] >= 32 || data[i] == '\n' || data[i] == '\r' {
			out = append(out, data[i])
		}
	}
	return string(out)
}

func inferDeviceFromBanner(banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "cisco"):
		return "Cisco network device"
	case strings.Contains(b, "linux"):
		return "Linux system"
	case strings.Contains(b, "windows"):
		return "Windows system"
	case strings.Contains(b, "router"):
		return "Router"
	case strings.Contains(b, "switch"):
		return "Network switch"
	case strings.Contains(b, "siemens") || strings.Contains(b, "ge ") || strings.Contains(b, "philips"):
		return "Medical device"
	default:
		return "Unknown"
	}
}

// TelnetFindings returns risk findings
func TelnetFindings(r TelnetResult, ip string, port int) []string {
	var findings []string
	if !r.Open {
		return findings
	}

	if r.NoPassword {
		findings = append(findings,
			fmt.Sprintf("CRITICAL: Telnet on %s:%d requires NO authentication — direct shell access", ip, port))
	} else if r.PromptFound {
		findings = append(findings,
			fmt.Sprintf("HIGH: Telnet login prompt on %s:%d — credentials transmitted in PLAINTEXT (sniffable)", ip, port))
	} else {
		findings = append(findings,
			fmt.Sprintf("MEDIUM: Telnet port open on %s:%d — insecure protocol, should be disabled", ip, port))
	}

	if r.DeviceHint != "" && r.DeviceHint != "Unknown" {
		findings = append(findings,
			fmt.Sprintf("INFO: Telnet device identified as: %s", r.DeviceHint))
	}

	return findings
}

// ── FHIR API ─────────────────────────────────────────────────────────────────

type FHIRResult struct {
	Found           bool
	Unauthenticated bool     // true if we got patient data without a token
	Endpoints       []string // which endpoints responded
	PatientDataLeak bool     // /Patient returned data
	ServerHeader    string
}

// Common FHIR endpoint paths to probe
var fhirPaths = []string{
	"/fhir/metadata",          // capability statement — always exists on FHIR servers
	"/fhir/Patient",           // patient records — should require auth
	"/fhir/Observation",       // lab results
	"/fhir/MedicationRequest", // prescriptions
	"/fhir/DiagnosticReport",  // radiology/lab reports
	"/api/fhir/metadata",
	"/api/fhir/Patient",
	"/r4/metadata", // FHIR R4
	"/r4/Patient",
	"/stu3/metadata", // FHIR STU3
	"/dme/metadata",  // Algeria DEM specific
	"/dem/Patient",
}

// CheckFHIR probes common FHIR API paths on HTTP/HTTPS ports
func CheckFHIR(ip string, port int) FHIRResult {
	result := FHIRResult{}

	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	for _, path := range fhirPaths {
		resp, server, status := httpGet(ip, port, path)
		if resp == "" {
			continue
		}

		if server != "" {
			result.ServerHeader = server
		}

		// Check if response looks like FHIR (JSON with resourceType)
		isFHIR := strings.Contains(resp, "resourceType") ||
			strings.Contains(resp, "CapabilityStatement") ||
			strings.Contains(resp, "fhir") ||
			strings.Contains(resp, "hl7.org")

		if !isFHIR {
			continue
		}

		result.Found = true
		result.Endpoints = append(result.Endpoints, fmt.Sprintf("%s://%s:%d%s (HTTP %d)", scheme, ip, port, path, status))

		// If we got patient data without auth, that's critical
		if strings.Contains(path, "Patient") && status == 200 {
			if strings.Contains(resp, "\"Patient\"") || strings.Contains(resp, "\"patient\"") {
				result.PatientDataLeak = true
				result.Unauthenticated = true
			}
		}

		// metadata without auth is a finding (reveals server capabilities)
		if strings.Contains(path, "metadata") && status == 200 {
			result.Unauthenticated = true
		}
	}

	return result
}

// httpGet performs a raw HTTP GET and returns body, server header, status code
func httpGet(ip string, port int, path string) (string, string, int) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return "", "", 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nAccept: application/fhir+json, application/json\r\n\r\n", path, ip)
	conn.Write([]byte(req))

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n == 0 {
		return "", "", 0
	}

	raw := string(buf[:n])

	// Parse status code
	status := 0
	if len(raw) > 12 && strings.HasPrefix(raw, "HTTP/") {
		fmt.Sscanf(raw[9:12], "%d", &status)
	}

	// Parse Server header
	server := ""
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[7:])
			break
		}
	}

	// Return body (after double CRLF)
	body := ""
	if idx := strings.Index(raw, "\r\n\r\n"); idx != -1 {
		body = raw[idx+4:]
	}

	return body, server, status
}

// FHIRFindings returns risk findings from FHIR check
func FHIRFindings(r FHIRResult, ip string, port int) []string {
	var findings []string
	if !r.Found {
		return findings
	}

	if r.PatientDataLeak {
		findings = append(findings,
			fmt.Sprintf("CRITICAL: FHIR API on %s:%d exposes PATIENT RECORDS without authentication — immediate PHI breach", ip, port))
	} else if r.Unauthenticated {
		findings = append(findings,
			fmt.Sprintf("HIGH: FHIR API on %s:%d accessible without authentication — server capabilities exposed", ip, port))
	} else {
		findings = append(findings,
			fmt.Sprintf("INFO: FHIR API detected on %s:%d — verify authentication is enforced on all endpoints", ip, port))
	}

	for _, ep := range r.Endpoints {
		findings = append(findings, fmt.Sprintf("  endpoint: %s", ep))
	}

	return findings
}
