package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type TLSResult struct {
	Enabled      bool
	Version      string
	CertExpiry   time.Time
	CertExpired  bool
	SelfSigned   bool
	CertCN       string
	WeakCipher   bool
	DaysUntilExp int
}

// CheckTLS attempts a TLS handshake and inspects the certificate
func CheckTLS(ip string, port int) TLSResult {
	address := fmt.Sprintf("%s:%d", ip, port)

	conf := &tls.Config{
		InsecureSkipVerify: true, // we want to inspect bad certs, not reject them
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		address,
		conf,
	)
	if err != nil {
		// TLS not available on this port
		return TLSResult{Enabled: false}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := TLSResult{Enabled: true}

	// TLS version
	switch state.Version {
	case tls.VersionTLS13:
		result.Version = "TLS 1.3"
	case tls.VersionTLS12:
		result.Version = "TLS 1.2"
	case tls.VersionTLS11:
		result.Version = "TLS 1.1 (deprecated)"
		result.WeakCipher = true
	case tls.VersionTLS10:
		result.Version = "TLS 1.0 (insecure)"
		result.WeakCipher = true
	default:
		result.Version = "SSL (critical - ancient)"
		result.WeakCipher = true
	}

	// Certificate inspection
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertCN = cert.Subject.CommonName
		result.CertExpiry = cert.NotAfter
		result.CertExpired = time.Now().After(cert.NotAfter)
		result.DaysUntilExp = int(time.Until(cert.NotAfter).Hours() / 24)

		// Self-signed = issuer == subject
		if cert.Issuer.String() == cert.Subject.String() {
			result.SelfSigned = true
		}

		// Check against trusted roots
		roots, _ := x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
		opts := x509.VerifyOptions{Roots: roots}
		if _, err := cert.Verify(opts); err != nil {
			result.SelfSigned = true
		}
	}

	return result
}

// TLSRisk converts a TLS result into risk findings
func TLSRisk(r TLSResult, port int) []string {
	var findings []string

	if !r.Enabled {
		// Only flag missing TLS on ports that SHOULD have it
		tlsPorts := map[int]string{
			443: "HTTPS", 8443: "HTTPS-alt",
			993: "IMAPS", 995: "POP3S", 636: "LDAPS",
		}
		if svc, ok := tlsPorts[port]; ok {
			findings = append(findings, fmt.Sprintf("CRITICAL: %s port %d has NO TLS encryption", svc, port))
		}
		// For DICOM/HL7 - plaintext is expected but still a finding
		if port == 104 || port == 11112 {
			findings = append(findings, "HIGH: DICOM running without TLS - patient imaging data transmitted in plaintext")
		}
		if port == 2575 || port == 2576 {
			findings = append(findings, "HIGH: HL7/MLLP running without TLS - patient records transmitted in plaintext")
		}
		return findings
	}

	if r.CertExpired {
		findings = append(findings, fmt.Sprintf("CRITICAL: SSL certificate EXPIRED %d days ago (CN: %s)", -r.DaysUntilExp, r.CertCN))
	} else if r.DaysUntilExp < 30 {
		findings = append(findings, fmt.Sprintf("HIGH: SSL certificate expires in %d days (CN: %s)", r.DaysUntilExp, r.CertCN))
	}

	if r.SelfSigned {
		findings = append(findings, fmt.Sprintf("MEDIUM: Self-signed certificate detected (CN: %s) - susceptible to MITM attacks", r.CertCN))
	}

	if r.WeakCipher {
		findings = append(findings, fmt.Sprintf("HIGH: Weak TLS version in use: %s - must upgrade to TLS 1.2+", r.Version))
	}

	return findings
}
