package scoring

import (
	"fmt"
	"strings"
)

// ── ISO 27001 control domains relevant to hospital networks ───────────────────

type Domain struct {
	Code        string
	Name        string
	Score       int // 0–100, computed from findings
	MaxDeducted int // how many points were taken off
	Findings    []ISOFinding
}

type ISOFinding struct {
	Control     string // e.g. "A.13.1.3"
	Title       string
	Description string
	Severity    string // CRITICAL, HIGH, MEDIUM, LOW
	Deduction   int    // points deducted from domain score
	Fix         string // what the pack does to fix this
}

type ISOReport struct {
	Overall     int
	Grade       string
	Domains     []Domain
	PackTier    string // "essentiel", "securite", "conformite"
	TotalCrit   int
	TotalHigh   int
	TotalMedium int
}

// ── Control → domain mapping ─────────────────────────────────────────────────

// Finding tags — what the scanner produces that we map to ISO controls
type ScanFindings struct {
	HasSMBv1          bool
	HasSMBNoSigning   bool
	HasRDPNoNLA       bool
	HasTelnet         bool
	HasFTPDefault     bool
	HasHTTPDefault    bool
	HasSNMPPublic     bool
	HasDICOMNoTLS     bool
	HasHL7NoTLS       bool
	HasFHIRNoAuth     bool
	HasVLANViolation  bool
	HasExpiredCert    bool
	HasWeakTLS        bool
	HasSelfSignedCert bool
	HasMySQLExposed   bool
	HasMSSQLExposed   bool
	HasMongoExposed   bool
	HasModbusExposed  bool
	HasOldSSH         bool
	HasWindowsXP      bool
	CriticalCount     int
	HighCount         int
	MediumCount       int
}

// ── Main scoring function ─────────────────────────────────────────────────────

func CalculateISO(f ScanFindings) ISOReport {
	report := ISOReport{}

	// Build each domain with its findings and score
	domains := []Domain{
		scoreA9(f),  // Access control
		scoreA10(f), // Cryptography
		scoreA12(f), // Operations security
		scoreA13(f), // Network security
		scoreA14(f), // System acquisition & maintenance
	}

	report.Domains = domains

	// Overall = weighted average
	// A.13 (network) and A.10 (crypto) weighted heavier for healthcare
	weights := map[string]float64{
		"A.9":  1.0,
		"A.10": 1.5, // crypto matters most for patient data
		"A.12": 1.0,
		"A.13": 1.5, // network segmentation is #1 ransomware vector
		"A.14": 0.8,
	}

	totalWeight := 0.0
	weightedScore := 0.0
	for _, d := range domains {
		w := weights[d.Code]
		weightedScore += float64(d.Score) * w
		totalWeight += w

		for _, finding := range d.Findings {
			switch finding.Severity {
			case "CRITICAL":
				report.TotalCrit++
			case "HIGH":
				report.TotalHigh++
			case "MEDIUM":
				report.TotalMedium++
			}
		}
	}

	report.Overall = int(weightedScore / totalWeight)
	report.Grade = gradeFromScore(report.Overall)
	report.PackTier = packTierFromScore(report.Overall, report.TotalCrit)

	return report
}

// ── Domain scorers ────────────────────────────────────────────────────────────

func scoreA9(f ScanFindings) Domain {
	d := Domain{Code: "A.9", Name: "Access control", Score: 100}

	if f.HasFTPDefault {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.9.4.3",
			Title:       "Default FTP credentials active",
			Description: "FTP server accepts admin/admin — full filesystem access without legitimate auth",
			Severity:    "CRITICAL",
			Deduction:   30,
			Fix:         "Change all default credentials, enforce strong password policy",
		})
	}
	if f.HasHTTPDefault {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.9.4.3",
			Title:       "Default HTTP admin credentials",
			Description: "Web admin panel accepts default credentials — device fully compromised",
			Severity:    "CRITICAL",
			Deduction:   25,
			Fix:         "Rotate all admin passwords, enforce MFA on admin panels",
		})
	}
	if f.HasFHIRNoAuth {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.9.4.1",
			Title:       "FHIR API unauthenticated",
			Description: "DEM patient records queryable with no authentication — full PHI exposure",
			Severity:    "CRITICAL",
			Deduction:   35,
			Fix:         "Implement OAuth2/SMART on FHIR, enforce Bearer token on all endpoints",
		})
	}
	if f.HasRDPNoNLA {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.9.4.2",
			Title:       "RDP without Network Level Authentication",
			Description: "RDP accessible pre-authentication — vulnerable to BlueKeep and brute force",
			Severity:    "HIGH",
			Deduction:   20,
			Fix:         "Enable NLA on all RDP endpoints, restrict to VPN only",
		})
	}
	if f.HasSNMPPublic {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.9.1.2",
			Title:       "SNMP community string 'public'",
			Description: "Default SNMP community exposes full device configuration and topology",
			Severity:    "HIGH",
			Deduction:   15,
			Fix:         "Change SNMP community strings, upgrade to SNMPv3 with authentication",
		})
	}

	d.Score = deductFromDomain(d.Score, d.Findings)
	return d
}

func scoreA10(f ScanFindings) Domain {
	d := Domain{Code: "A.10", Name: "Cryptography", Score: 100}

	if f.HasDICOMNoTLS {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.10.1.1",
			Title:       "DICOM transmitted without TLS",
			Description: "Medical imaging data (X-rays, MRI) transmitted in plaintext — interceptable by anyone on the network",
			Severity:    "CRITICAL",
			Deduction:   35,
			Fix:         "Deploy TLS gateway for DICOM, enforce Secure Transport Connection Profile",
		})
	}
	if f.HasHL7NoTLS {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.10.1.1",
			Title:       "HL7/MLLP transmitted without TLS",
			Description: "Patient health records transmitted in cleartext — HL7 v2 has no built-in encryption",
			Severity:    "CRITICAL",
			Deduction:   35,
			Fix:         "Wrap HL7 in TLS tunnel or deploy MLLP over TLS gateway",
		})
	}
	if f.HasWeakTLS {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.10.1.2",
			Title:       "Weak TLS version in use",
			Description: "TLS 1.0/1.1 detected — deprecated, vulnerable to BEAST/POODLE attacks",
			Severity:    "HIGH",
			Deduction:   20,
			Fix:         "Enforce TLS 1.2 minimum, TLS 1.3 preferred on all endpoints",
		})
	}
	if f.HasExpiredCert {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.10.1.2",
			Title:       "Expired SSL certificate",
			Description: "Expired certificate breaks trust chain — browsers warn users, MITM attacks possible",
			Severity:    "HIGH",
			Deduction:   15,
			Fix:         "Renew certificate, implement auto-renewal with Let's Encrypt or internal CA",
		})
	}
	if f.HasSelfSignedCert {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.10.1.2",
			Title:       "Self-signed certificate",
			Description: "Self-signed cert cannot be verified — susceptible to MITM, no PKI chain",
			Severity:    "MEDIUM",
			Deduction:   10,
			Fix:         "Replace with certificate signed by trusted CA",
		})
	}

	d.Score = deductFromDomain(d.Score, d.Findings)
	return d
}

func scoreA12(f ScanFindings) Domain {
	d := Domain{Code: "A.12", Name: "Operations security", Score: 100}

	if f.HasSMBv1 {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.12.6.1",
			Title:       "SMBv1 protocol active (EternalBlue)",
			Description: "SMBv1 is the ransomware vector used by WannaCry, NotPetya. Microsoft deprecated it in 2014. Still present on hospital PCs.",
			Severity:    "CRITICAL",
			Deduction:   40,
			Fix:         "Disable SMBv1 via Group Policy: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
		})
	}
	if f.HasWindowsXP {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.12.6.1",
			Title:       "End-of-life operating system detected",
			Description: "Windows XP/7 detected — no security patches since 2014/2020. Every known CVE is permanently unpatched.",
			Severity:    "CRITICAL",
			Deduction:   30,
			Fix:         "Migrate to supported OS. Isolate legacy devices in dedicated VLAN with strict firewall rules as interim measure.",
		})
	}
	if f.HasModbusExposed {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.12.6.1",
			Title:       "Modbus protocol exposed",
			Description: "Industrial/medical device control protocol with no authentication — direct manipulation of connected medical devices possible",
			Severity:    "CRITICAL",
			Deduction:   35,
			Fix:         "Isolate Modbus devices behind dedicated firewall, whitelist only authorized controller IPs",
		})
	}
	if f.HasOldSSH {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.12.6.1",
			Title:       "Outdated SSH version",
			Description: "OpenSSH version with known CVEs detected — remote code execution possible",
			Severity:    "HIGH",
			Deduction:   20,
			Fix:         "Update OpenSSH to 9.x, disable root login, enforce key-based authentication",
		})
	}

	d.Score = deductFromDomain(d.Score, d.Findings)
	return d
}

func scoreA13(f ScanFindings) Domain {
	d := Domain{Code: "A.13", Name: "Network security", Score: 100}

	if f.HasVLANViolation {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.13.1.3",
			Title:       "Network segmentation absent",
			Description: "Medical devices, admin PCs, and guest WiFi share the same network — one compromised device reaches everything",
			Severity:    "CRITICAL",
			Deduction:   40,
			Fix:         "Implement VLAN segmentation: medical VLAN, admin VLAN, guest VLAN with inter-VLAN firewall rules",
		})
	}
	if f.HasSMBNoSigning {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.13.1.1",
			Title:       "SMB signing not enforced",
			Description: "Without SMB signing, NTLM relay attacks allow credential theft across the network — primary lateral movement vector",
			Severity:    "HIGH",
			Deduction:   25,
			Fix:         "Enable RequireSecuritySignature via Group Policy on all Windows hosts",
		})
	}
	if f.HasTelnet {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.13.2.1",
			Title:       "Telnet protocol in use",
			Description: "Telnet sends all data including passwords in plaintext — trivially intercepted with Wireshark on the same network",
			Severity:    "HIGH",
			Deduction:   20,
			Fix:         "Disable Telnet on all devices, replace with SSH. On Cisco: no service telnet",
		})
	}
	if f.HasMySQLExposed || f.HasMSSQLExposed || f.HasMongoExposed {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.13.1.1",
			Title:       "Database port exposed on network",
			Description: "Database management port directly reachable from hospital network — patient database one credential away from full exfiltration",
			Severity:    "CRITICAL",
			Deduction:   35,
			Fix:         "Move databases behind application layer, bind to localhost only, use VPN for admin access",
		})
	}

	d.Score = deductFromDomain(d.Score, d.Findings)
	return d
}

func scoreA14(f ScanFindings) Domain {
	d := Domain{Code: "A.14", Name: "System acquisition", Score: 100}

	if f.HasFHIRNoAuth {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.14.2.5",
			Title:       "DEM/FHIR API lacks security by design",
			Description: "FHIR API deployed without authentication layer — system acquired/deployed without security requirements",
			Severity:    "CRITICAL",
			Deduction:   30,
			Fix:         "Implement SMART on FHIR authorization layer, add API gateway with rate limiting and audit logging",
		})
	}
	if f.HasDICOMNoTLS {
		d.Findings = append(d.Findings, ISOFinding{
			Control:     "A.14.1.2",
			Title:       "DICOM deployed without encryption requirements",
			Description: "Medical imaging system acquired and deployed without enforcing TLS — security not included in procurement requirements",
			Severity:    "HIGH",
			Deduction:   20,
			Fix:         "Add TLS requirement to all future medical system procurement contracts",
		})
	}

	d.Score = deductFromDomain(d.Score, d.Findings)
	return d
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func deductFromDomain(start int, findings []ISOFinding) int {
	score := start
	for _, f := range findings {
		score -= f.Deduction
	}
	if score < 0 {
		score = 0
	}
	return score
}

func gradeFromScore(score int) string {
	switch {
	case score >= 90:
		return "A — ISO compliant"
	case score >= 75:
		return "B — Minor gaps"
	case score >= 55:
		return "C — Significant risk"
	case score >= 35:
		return "D — High risk"
	default:
		return "F — Critical non-compliance"
	}
}

func packTierFromScore(score int, criticals int) string {
	if score < 35 || criticals >= 4 {
		return "conformite" // worst case → full pack
	}
	if score < 60 || criticals >= 2 {
		return "securite"
	}
	return "essentiel"
}

// ParseFindings converts raw scanner output strings into a ScanFindings struct
func ParseFindings(allFindings []string, smbOpen bool, smbV1 bool, smbSigning bool,
	rdpOpen bool, rdpNLA bool, snmpVuln bool) ScanFindings {

	f := ScanFindings{}

	combined := strings.Join(allFindings, " ")
	lower := strings.ToLower(combined)

	f.HasSMBv1 = smbV1
	f.HasSMBNoSigning = smbOpen && !smbSigning
	f.HasRDPNoNLA = rdpOpen && !rdpNLA
	f.HasSNMPPublic = snmpVuln

	f.HasTelnet = strings.Contains(lower, "telnet")
	f.HasFTPDefault = strings.Contains(lower, "default ftp")
	f.HasHTTPDefault = strings.Contains(lower, "default http")
	f.HasDICOMNoTLS = strings.Contains(lower, "dicom") && strings.Contains(lower, "no tls")
	f.HasHL7NoTLS = strings.Contains(lower, "hl7") && strings.Contains(lower, "tls")
	f.HasFHIRNoAuth = strings.Contains(lower, "fhir") && (strings.Contains(lower, "unauthenticated") || strings.Contains(lower, "patient records"))
	f.HasVLANViolation = strings.Contains(lower, "vlan") && strings.Contains(lower, "failed")
	f.HasExpiredCert = strings.Contains(lower, "expired")
	f.HasWeakTLS = strings.Contains(lower, "weak tls") || strings.Contains(lower, "tls 1.0") || strings.Contains(lower, "tls 1.1")
	f.HasSelfSignedCert = strings.Contains(lower, "self-signed")
	f.HasMySQLExposed = strings.Contains(lower, "mysql")
	f.HasMSSQLExposed = strings.Contains(lower, "mssql")
	f.HasMongoExposed = strings.Contains(lower, "mongodb")
	f.HasModbusExposed = strings.Contains(lower, "modbus")
	f.HasOldSSH = strings.Contains(lower, "openssh_6") || strings.Contains(lower, "openssh_7.4") || strings.Contains(lower, "openssh_7.6")
	f.HasWindowsXP = strings.Contains(lower, "windows xp") || strings.Contains(lower, "end of life")

	for _, finding := range allFindings {
		switch {
		case strings.HasPrefix(finding, "CRITICAL"):
			f.CriticalCount++
		case strings.HasPrefix(finding, "HIGH"):
			f.HighCount++
		case strings.HasPrefix(finding, "MEDIUM"):
			f.MediumCount++
		}
	}

	return f
}

// PrettyPrint prints the ISO report to terminal
func PrettyPrint(r ISOReport) {
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Printf("  ISO 27001 COMPLIANCE SCORE: %d/100 — %s\n", r.Overall, r.Grade)
	fmt.Printf("  Findings: %d CRITICAL  %d HIGH  %d MEDIUM\n",
		r.TotalCrit, r.TotalHigh, r.TotalMedium)
	fmt.Println(strings.Repeat("═", 60))

	for _, d := range r.Domains {
		bar := scoreBar(d.Score)
		fmt.Printf("\n  %s — %s\n  %s %d/100\n", d.Code, d.Name, bar, d.Score)
		for _, finding := range d.Findings {
			prefix := "  [!] "
			if finding.Severity == "CRITICAL" {
				prefix = "  [!!!] "
			}
			fmt.Printf("%s%s (%s): %s\n", prefix, finding.Control, finding.Severity, finding.Title)
		}
	}
	fmt.Println()
}

func scoreBar(score int) string {
	filled := score / 10
	bar := "["
	for i := 0; i < 10; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	return bar + "]"
}
