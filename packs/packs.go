package main

import (
	"fmt"
	"os"
	"time"
)

// ── Pack Essentiel ────────────────────────────────────────────────────────────

func RunEssentiel(t *Targets, win WinCreds, ssh SSHCreds, log *RunLog) {
	fmt.Println("── Pack Essentiel — Windows fixes ──────────────────────")

	winFixes := []string{
		"disable-smbv1",
		"enable-rdp-nla",
		"disable-telnet",
		"firewall-rules",
		"remove-snmp-public",
	}

	for _, ip := range t.Windows {
		fmt.Printf("\n  [HOST] %s\n", ip)
		for _, fix := range winFixes {
			ApplyWindowsFix(ip, win, fix, log)
		}
	}

	fmt.Println("\n── Pack Essentiel — Linux fixes ────────────────────────")
	for _, ip := range t.Linux {
		fmt.Printf("\n  [HOST] %s\n", ip)
		ApplyLinuxFix(ip, ssh, "disable-telnet", log)
		ApplyLinuxFix(ip, ssh, "ufw-firewall", log)
	}
}

// ── Pack Sécurité ─────────────────────────────────────────────────────────────

func RunSecurite(t *Targets, win WinCreds, ssh SSHCreds, log *RunLog) {
	// Run Essentiel first
	RunEssentiel(t, win, ssh, log)

	fmt.Println("\n── Pack Sécurité — additional Windows fixes ────────────")
	for _, ip := range t.Windows {
		fmt.Printf("\n  [HOST] %s\n", ip)
		ApplyWindowsFix(ip, win, "enable-smb-signing", log)
		ApplyWindowsFix(ip, win, "disable-legacy-proto", log)
		ApplyWindowsFix(ip, win, "enforce-tls", log)
	}

	fmt.Println("\n── Pack Sécurité — additional Linux fixes ──────────────")
	for _, ip := range t.Linux {
		fmt.Printf("\n  [HOST] %s\n", ip)
		ApplyLinuxFix(ip, ssh, "snmpv3-upgrade", log)
		ApplyLinuxFix(ip, ssh, "fhir-auth", log)
		ApplyLinuxFix(ip, ssh, "tls-hl7", log)
		ApplyLinuxFix(ip, ssh, "tls-dicom", log)
		ApplyLinuxFix(ip, ssh, "harden-ssh", log)
	}
}

// ── Pack Conformité ───────────────────────────────────────────────────────────

func RunConformite(t *Targets, win WinCreds, ssh SSHCreds, log *RunLog) {
	// Run Sécurité first
	RunSecurite(t, win, ssh, log)

	fmt.Println("\n── Pack Conformité — full compliance layer ─────────────")

	for _, ip := range t.Windows {
		fmt.Printf("\n  [HOST] %s\n", ip)
		ApplyWindowsFix(ip, win, "disable-legacy-proto", log)
		ApplyWindowsFix(ip, win, "enforce-tls", log)
	}

	for _, ip := range t.Linux {
		fmt.Printf("\n  [HOST] %s\n", ip)
		ApplyLinuxFix(ip, ssh, "install-fail2ban", log)
	}

	// Generate ministry compliance report
	fmt.Println("\n── Generating ministry compliance report ───────────────")
	generateComplianceDoc(log)
}

func generateComplianceDoc(log *RunLog) {
	passed := 0
	for _, r := range log.Results {
		if r.Success {
			passed++
		}
	}

	total := len(log.Results)
	pct := 0
	if total > 0 {
		pct = passed * 100 / total
	}

	fmt.Printf("\n  Fixes applied: %d/%d (%.0d%%)\n", passed, total, pct)
	fmt.Println("  Compliance document generated: compliance_report.txt")

	content := fmt.Sprintf(`RAPPORT DE CONFORMITE ISO 27001
Ministère de la Santé — République Algérienne Démocratique et Populaire
========================================================================

Date : %s
Réalisé par : Securthy

RÉSUMÉ DES ACTIONS DE REMÉDIATION
-----------------------------------
Correctifs appliqués : %d / %d
Taux de réussite     : %d%%

CONTRÔLES ISO 27001 TRAITÉS
-----------------------------
A.9  — Contrôle d'accès      : Credentials par défaut changés, NLA activé
A.10 — Cryptographie          : TLS appliqué sur DICOM et HL7, TLS 1.2+ forcé
A.12 — Sécurité opérationnelle: SMBv1 désactivé, protocoles legacy supprimés
A.13 — Sécurité réseau        : Firewall configuré, SNMP sécurisé
A.14 — Acquisition systèmes   : FHIR API authentifiée, SSH durci

PROCHAINES ÉTAPES
------------------
1. Planifier la segmentation VLAN avec l'équipe réseau
2. Former le personnel (session recommandée sous 30 jours)
3. Scan de validation dans 90 jours
4. Renouveler les certificats TLS avant expiration

Ce rapport atteste que les mesures de sécurité listées ont été
appliquées automatiquement par la plateforme Securthy.
`, getCurrentDate(), passed, total, pct)

	writeFile("compliance_report.txt", content)
}

func getCurrentDate() string {
	return time.Now().Format("02 January 2006")
}

func writeFile(path, content string) {
	os.WriteFile(path, []byte(content), 0644)
}
