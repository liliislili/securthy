package email

import (
	"fmt"
	"net"
	"strings"
)

type EmailSecurityResult struct {
	Domain     string
	SPF        SPFResult
	DKIM       DKIMResult
	DMARC      DMARCResult
	Vulnerable bool
	Findings   []string
}

type SPFResult struct {
	Exists  bool
	Record  string
	Valid   bool
	Finding string
}

type DKIMResult struct {
	Exists  bool
	Record  string
	Finding string
}

type DMARCResult struct {
	Exists  bool
	Record  string
	Policy  string // none, quarantine, reject
	Finding string
}

// CheckEmailSecurity checks SPF, DKIM, DMARC for a domain
// This tells you if the hospital's email can be spoofed for phishing
func CheckEmailSecurity(domain string) EmailSecurityResult {
	result := EmailSecurityResult{Domain: domain}

	result.SPF = checkSPF(domain)
	result.DKIM = checkDKIM(domain)
	result.DMARC = checkDMARC(domain)

	// Build findings
	if !result.SPF.Exists {
		result.Findings = append(result.Findings,
			fmt.Sprintf("CRITICAL: No SPF record for %s — anyone can send emails pretending to be from this hospital", domain))
		result.Vulnerable = true
	} else if !result.SPF.Valid {
		result.Findings = append(result.Findings,
			fmt.Sprintf("HIGH: SPF record exists but is misconfigured for %s — spoofing partially possible", domain))
		result.Vulnerable = true
	} else {
		result.Findings = append(result.Findings,
			fmt.Sprintf("OK: SPF configured for %s", domain))
	}

	if !result.DKIM.Exists {
		result.Findings = append(result.Findings,
			fmt.Sprintf("HIGH: No DKIM record for %s — emails cannot be cryptographically verified", domain))
		result.Vulnerable = true
	}

	if !result.DMARC.Exists {
		result.Findings = append(result.Findings,
			fmt.Sprintf("CRITICAL: No DMARC record for %s — no policy to reject spoofed emails", domain))
		result.Vulnerable = true
	} else if result.DMARC.Policy == "none" {
		result.Findings = append(result.Findings,
			fmt.Sprintf("HIGH: DMARC policy is 'none' for %s — spoofed emails still delivered, only monitored", domain))
		result.Vulnerable = true
	} else if result.DMARC.Policy == "quarantine" {
		result.Findings = append(result.Findings,
			fmt.Sprintf("MEDIUM: DMARC policy is 'quarantine' for %s — upgrade to 'reject' for full protection", domain))
	} else if result.DMARC.Policy == "reject" {
		result.Findings = append(result.Findings,
			fmt.Sprintf("OK: DMARC policy is 'reject' for %s — spoofed emails blocked", domain))
	}

	return result
}

func checkSPF(domain string) SPFResult {
	result := SPFResult{}

	txts, err := net.LookupTXT(domain)
	if err != nil {
		return result
	}

	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			result.Exists = true
			result.Record = txt

			// Basic validation
			if strings.Contains(txt, "~all") {
				result.Valid = true
				result.Finding = "SPF with softfail (~all) — upgrade to -all for strict enforcement"
			} else if strings.Contains(txt, "-all") {
				result.Valid = true
				result.Finding = "SPF with hardfail (-all) — correctly configured"
			} else if strings.Contains(txt, "+all") {
				result.Valid = false
				result.Finding = "CRITICAL: SPF with +all — allows ANYONE to send as this domain"
			}
			break
		}
	}

	return result
}

func checkDKIM(domain string) DKIMResult {
	result := DKIMResult{}

	// Check common DKIM selectors
	selectors := []string{"default", "google", "mail", "email", "dkim", "k1", "selector1", "selector2"}

	for _, selector := range selectors {
		dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
		txts, err := net.LookupTXT(dkimDomain)
		if err != nil {
			continue
		}
		for _, txt := range txts {
			if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "p=") {
				result.Exists = true
				result.Record = txt
				result.Finding = fmt.Sprintf("DKIM found with selector '%s'", selector)
				return result
			}
		}
	}

	result.Finding = "No DKIM record found on common selectors"
	return result
}

func checkDMARC(domain string) DMARCResult {
	result := DMARCResult{}

	dmarcDomain := "_dmarc." + domain
	txts, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		return result
	}

	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			result.Exists = true
			result.Record = txt

			// Extract policy
			for _, part := range strings.Split(txt, ";") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "p=") {
					result.Policy = strings.TrimPrefix(part, "p=")
					break
				}
			}
			return result
		}
	}

	return result
}
func Run(domain string) float64 {
	result := CheckEmailSecurity(domain)

	if result.Vulnerable {
		// critical exposure (spoofable identity)
		if !result.SPF.Exists || !result.DMARC.Exists {
			return 100.0
		}

		// partial security
		return 75.0
	}

	// strong configuration
	return 20.0
}