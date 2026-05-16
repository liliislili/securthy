package phishing

import (
	"fmt"
	"net"
	"strings"
	"time"

	"go-scanner/internal/human/email"
)

type PhishingRisk struct {
	Domain          string
	CanBeSpoofed    bool
	MissingControls []string
	RiskLevel       string
	SMTPOpen        bool
	AcceptsRelay    bool
	Findings        []string
}

func AssessPhishingRisk(domain string, mailServerIP string) PhishingRisk {
	risk := PhishingRisk{Domain: domain}

	emailSec := email.CheckEmailSecurity(domain)

	if !emailSec.SPF.Exists {
		risk.CanBeSpoofed = true
		risk.MissingControls = append(risk.MissingControls, "SPF")
	}
	if !emailSec.DKIM.Exists {
		risk.MissingControls = append(risk.MissingControls, "DKIM")
	}
	if !emailSec.DMARC.Exists {
		risk.CanBeSpoofed = true
		risk.MissingControls = append(risk.MissingControls, "DMARC")
	} else if emailSec.DMARC.Policy == "none" {
		risk.CanBeSpoofed = true
		risk.MissingControls = append(risk.MissingControls, "DMARC-enforcement")
	}

	if mailServerIP != "" {
		risk.SMTPOpen = checkSMTPOpen(mailServerIP)
		if risk.SMTPOpen {
			risk.AcceptsRelay = checkOpenRelay(mailServerIP, domain)
		}
	}

	if risk.CanBeSpoofed {
		risk.RiskLevel = "CRITICAL"
		risk.Findings = append(risk.Findings,
			fmt.Sprintf("CRITICAL: Domain '%s' can be spoofed — missing: %s",
				domain, strings.Join(risk.MissingControls, ", ")))
		risk.Findings = append(risk.Findings,
			"CRITICAL: Attackers can send emails appearing to come from hospital doctors/admin")
		risk.Findings = append(risk.Findings,
			"CRITICAL: Patients and staff vulnerable to phishing using hospital identity")
	}

	if risk.AcceptsRelay {
		risk.RiskLevel = "CRITICAL"
		risk.Findings = append(risk.Findings,
			fmt.Sprintf("CRITICAL: Mail server %s is an OPEN RELAY — can be used to send spam/phishing from hospital IP", mailServerIP))
	}

	risk.Findings = append(risk.Findings,
		"RECOMMENDATION: Run phishing awareness campaign (ISO 27001 A.6.3.1) — test staff click rates on simulated phishing emails")

	return risk
}

func checkSMTPOpen(ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:25", ip), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func checkOpenRelay(ip, domain string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:25", ip), 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 512)
	conn.Read(buf)

	fmt.Fprintf(conn, "EHLO scanner.healthguard.dz\r\n")
	conn.Read(buf)

	fmt.Fprintf(conn, "MAIL FROM:<test@external-domain.com>\r\n")
	n, _ := conn.Read(buf)
	mailResp := string(buf[:n])

	fmt.Fprintf(conn, "RCPT TO:<test@another-external.com>\r\n")
	n, _ = conn.Read(buf)
	rcptResp := string(buf[:n])

	fmt.Fprintf(conn, "QUIT\r\n")

	return strings.Contains(mailResp, "250") && strings.Contains(rcptResp, "250")
}

func GeneratePhishingReport(domain string, risk PhishingRisk) string {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════\n")
	sb.WriteString("  RAPPORT — SIMULATION DE PHISHING\n")
	sb.WriteString("  Conformité ISO 27001 — Contrôle A.6.3.1\n")
	sb.WriteString("═══════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("Domaine analysé : %s\n", domain))
	sb.WriteString(fmt.Sprintf("Niveau de risque : %s\n\n", risk.RiskLevel))

	sb.WriteString("VULNÉRABILITÉS DÉTECTÉES:\n")
	for _, f := range risk.Findings {
		sb.WriteString(fmt.Sprintf("  • %s\n", f))
	}

	sb.WriteString("\n\nPLAN DE SIMULATION PROPOSÉ:\n")
	sb.WriteString("─────────────────────────────\n")
	sb.WriteString("Phase 1 — Email de phishing simulé (avec autorisation écrite)\n")
	sb.WriteString("  • Envoi d'un email imitant une communication DEM/MSPRH\n")
	sb.WriteString("  • Cible: tous les employés de l'établissement\n")
	sb.WriteString("  • Suivi: qui a cliqué, qui a saisi des credentials\n\n")

	sb.WriteString("Phase 2 — Analyse des résultats\n")
	sb.WriteString("  • Taux de clics (objectif: < 5% après formation)\n")
	sb.WriteString("  • Taux de saisie de credentials (objectif: 0%)\n")
	sb.WriteString("  • Département le plus vulnérable\n\n")

	sb.WriteString("Phase 3 — Formation ciblée\n")
	sb.WriteString("  • Session de sensibilisation pour les cliqueurs\n")
	sb.WriteString("  • Guide de reconnaissance des emails suspects\n")
	sb.WriteString("  • Re-test après 30 jours\n\n")

	sb.WriteString("CORRECTIONS TECHNIQUES REQUISES:\n")
	sb.WriteString("  1. Configurer SPF avec -all (rejet strict)\n")
	sb.WriteString("  2. Déployer DKIM sur le serveur mail\n")
	sb.WriteString("  3. Passer DMARC policy de 'none' à 'reject'\n")
	sb.WriteString("  4. Fermer le relai SMTP ouvert si détecté\n\n")

	sb.WriteString("Note: Cette simulation nécessite une autorisation écrite\n")
	sb.WriteString("du Directeur de l'établissement avant exécution.\n")

	return sb.String()
}

func Run(emailAddr string, ip string) float64 {
	domain := emailAddr
	if strings.Contains(emailAddr, "@") {
		parts := strings.Split(emailAddr, "@")
		domain = parts[1]
	}

	risk := AssessPhishingRisk(domain, ip)

	if risk.AcceptsRelay {
		return 100.0
	}
	if risk.CanBeSpoofed {
		return 90.0
	}
	if len(risk.MissingControls) > 0 {
		return 70.0
	}
	return 20.0
}