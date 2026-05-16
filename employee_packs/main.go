package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"go-scanner/internal/human"
)

type EmployeeAction struct {
	EmployeeID string   `json:"employee_id"`
	Name       string   `json:"name"`
	Role       string   `json:"role"`
	Risk       float64  `json:"risk"`
	Actions    []Action `json:"actions"`
}

type Action struct {
	Priority    int    `json:"priority"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	ISOControl  string `json:"iso_control"`
	Deadline    string `json:"deadline"`
}

type RemediationPlan struct {
	GeneratedAt      string           `json:"generated_at"`
	TotalEmployees   int              `json:"total_employees"`
	CriticalRisk     []string         `json:"critical_risk_employees"`
	HighRisk         []string         `json:"high_risk_employees"`
	PhishingTraining []string         `json:"needs_phishing_training"`
	PasswordPolicy   []string         `json:"needs_password_policy"`
	WiFiAwareness    []string         `json:"needs_wifi_awareness"`
	Actions          []EmployeeAction `json:"employee_actions"`
	GlobalActions    []Action         `json:"global_actions"`
	EstimatedCost    string           `json:"estimated_cost_dzd"`
	Duration         string           `json:"implementation_duration"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println(`
Securthy DZ — Employee Remediation Pack

Usage:
  ./employee_packs_bin employee_report_<timestamp>.json

Workflow:
  ./employee_bin employees.json              # scan first
  ./employee_packs_bin employee_report_*.json  # then remediate
`)
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("[!] Cannot read report:", err)
		os.Exit(1)
	}

	var results []human.HumanScanResult
	if err := json.Unmarshal(data, &results); err != nil {
		var wrapped struct {
			Employees []human.HumanScanResult `json:"employees"`
		}
		if err2 := json.Unmarshal(data, &wrapped); err2 != nil {
			fmt.Println("[!] Invalid format:", err)
			os.Exit(1)
		}
		results = wrapped.Employees
	}

	if len(results) == 0 {
		fmt.Println("[!] No employee results found")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║   Securthy DZ — Employee Remediation Pack            ║")
	fmt.Printf("║   Processing %-3d employees                              ║\n", len(results))
	fmt.Println("╚══════════════════════════════════════════════════════════╝")

	plan := buildPlan(results)
	printPlan(plan)

	ts := fmt.Sprintf("%d", time.Now().Unix())
	doc := generateDoc(plan, results)
	os.WriteFile("employee_remediation_"+ts+".txt", []byte(doc), 0644)
	jsonData, _ := json.MarshalIndent(plan, "", "  ")
	os.WriteFile("employee_remediation_"+ts+".json", jsonData, 0644)

	fmt.Printf("\n[+] Remediation plan: employee_remediation_%s.txt\n", ts)
	fmt.Printf("[+] JSON summary:     employee_remediation_%s.json\n", ts)
}

func buildPlan(results []human.HumanScanResult) RemediationPlan {
	plan := RemediationPlan{
		GeneratedAt:    time.Now().Format(time.RFC3339),
		TotalEmployees: len(results),
	}

	for _, r := range results {
		ea := EmployeeAction{
			EmployeeID: r.EmployeeID,
			Name:       r.Name,
			Role:       r.Role,
			Risk:       r.TotalRisk,
		}

		if r.TotalRisk >= 80 {
			plan.CriticalRisk = append(plan.CriticalRisk, r.Name)
		} else if r.TotalRisk >= 60 {
			plan.HighRisk = append(plan.HighRisk, r.Name)
		}

		p := 1
		if r.Phishing >= 70 {
			plan.PhishingTraining = append(plan.PhishingTraining, r.Name)
			ea.Actions = append(ea.Actions, Action{p, "phishing",
				"Formation anti-phishing obligatoire",
				"Formation 2h sur reconnaissance emails suspects. Re-test après 30 jours.",
				"A.6.3.1", "7 jours"})
			p++
		}
		if r.Password >= 60 {
			plan.PasswordPolicy = append(plan.PasswordPolicy, r.Name)
			ea.Actions = append(ea.Actions, Action{p, "password",
				"Changement immédiat des mots de passe",
				"Minimum 12 caractères, complexité requise. Activer MFA si disponible.",
				"A.5.17", "24 heures"})
			p++
		}
		if r.WiFi >= 60 {
			plan.WiFiAwareness = append(plan.WiFiAwareness, r.Name)
			ea.Actions = append(ea.Actions, Action{p, "wifi",
				"Sensibilisation aux risques WiFi",
				"Interdire WiFi non sécurisé. VPN obligatoire sur mobile.",
				"A.8.20", "14 jours"})
			p++
		}
		if r.Privilege >= 70 {
			ea.Actions = append(ea.Actions, Action{p, "privilege",
				"Révision des droits d'accès",
				fmt.Sprintf("Rôle '%s' avec privilèges élevés. Appliquer principe moindre privilège.", r.Role),
				"A.5.18", "48 heures"})
			p++
		}
		if r.USB >= 70 {
			ea.Actions = append(ea.Actions, Action{p, "usb",
				"Restriction des périphériques USB",
				"Bloquer USB non autorisées via GPO. Autoriser uniquement clés chiffrées approuvées.",
				"A.8.12", "7 jours"})
			p++
		}
		if r.Email >= 60 {
			ea.Actions = append(ea.Actions, Action{p, "email",
				"Configuration sécurité email",
				"Configurer SPF/DKIM/DMARC. Former l'employé à vérifier les expéditeurs.",
				"A.8.23", "14 jours"})
		}

		plan.Actions = append(plan.Actions, ea)
	}

	plan.GlobalActions = []Action{
		{1, "policy", "Charte informatique — mise à jour",
			"Rédiger et faire signer une charte informatique couvrant: mots de passe, USB, phishing, données DEM.",
			"A.6.2", "30 jours"},
		{2, "training", "Session de sensibilisation collective",
			"Formation 3h pour tout le personnel: cybersécurité hospitalière, protection données DEM/FHIR.",
			"A.6.3.1", "30 jours"},
		{3, "phishing_sim", "Campagne de simulation de phishing",
			"Email de test envoyé à tous. Mesurer taux de clic. Former les cliqueurs immédiatement.",
			"A.6.3.1", "60 jours"},
		{4, "access", "Audit des accès au DEM",
			"Vérifier accès DEM. Révoquer comptes inutilisés depuis 90 jours.",
			"A.5.15", "14 jours"},
		{5, "incident", "Procédure de signalement incidents",
			"Former le personnel: signaler emails suspects, clés USB trouvées, accès non autorisés.",
			"A.6.8", "30 jours"},
	}

	base := 50000 + (len(results) * 8000) + (len(plan.CriticalRisk) * 15000) + (len(plan.HighRisk) * 8000)
	plan.EstimatedCost = fmt.Sprintf("%d – %d DZD", base, base+50000)
	plan.Duration = "30–60 jours"
	return plan
}

func printPlan(plan RemediationPlan) {
	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Printf("  PLAN DE REMÉDIATION — %d employés\n", plan.TotalEmployees)
	fmt.Println(strings.Repeat("═", 60))

	if len(plan.CriticalRisk) > 0 {
		fmt.Printf("\n  🔴 Risque CRITIQUE (%d): %s\n", len(plan.CriticalRisk), strings.Join(plan.CriticalRisk, ", "))
	}
	if len(plan.HighRisk) > 0 {
		fmt.Printf("  🟠 Risque ÉLEVÉ (%d): %s\n", len(plan.HighRisk), strings.Join(plan.HighRisk, ", "))
	}

	fmt.Printf("\n  Formation phishing requise : %d employés\n", len(plan.PhishingTraining))
	fmt.Printf("  Politique mots de passe   : %d employés\n", len(plan.PasswordPolicy))
	fmt.Printf("  Sensibilisation WiFi      : %d employés\n", len(plan.WiFiAwareness))

	fmt.Println("\n  Actions par employé:")
	for _, ea := range plan.Actions {
		if len(ea.Actions) == 0 {
			continue
		}
		fmt.Printf("\n  [%s] %s — %.0f/100\n", ea.Role, ea.Name, ea.Risk)
		for _, a := range ea.Actions {
			fmt.Printf("    %d. [%s] %s — %s\n", a.Priority, a.ISOControl, a.Title, a.Deadline)
		}
	}

	fmt.Println("\n  Actions globales:")
	for _, a := range plan.GlobalActions {
		fmt.Printf("  %d. [%s] %s (%s)\n", a.Priority, a.ISOControl, a.Title, a.Deadline)
	}

	fmt.Printf("\n  Coût estimé : %s\n", plan.EstimatedCost)
	fmt.Printf("  Durée       : %s\n", plan.Duration)
	fmt.Println(strings.Repeat("═", 60))
}

func generateDoc(plan RemediationPlan, results []human.HumanScanResult) string {
	var sb strings.Builder
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("  PLAN DE REMÉDIATION — SÉCURITÉ DU PERSONNEL\n")
	sb.WriteString("  Securthy DZ — Conformité ISO 27001:2022\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")
	sb.WriteString(fmt.Sprintf("Date           : %s\n", time.Now().Format("02 January 2006 à 15:04")))
	sb.WriteString(fmt.Sprintf("Employés       : %d\n", plan.TotalEmployees))
	sb.WriteString(fmt.Sprintf("Durée estimée  : %s\n", plan.Duration))
	sb.WriteString(fmt.Sprintf("Coût estimé    : %s\n\n", plan.EstimatedCost))

	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	sb.WriteString("1. RÉSUMÉ\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n\n")
	sb.WriteString(fmt.Sprintf("  • %d employé(s) en risque CRITIQUE\n", len(plan.CriticalRisk)))
	sb.WriteString(fmt.Sprintf("  • %d employé(s) en risque ÉLEVÉ\n", len(plan.HighRisk)))
	sb.WriteString(fmt.Sprintf("  • %d employé(s) nécessitent formation phishing\n", len(plan.PhishingTraining)))
	sb.WriteString(fmt.Sprintf("  • %d employé(s) nécessitent changement mot de passe\n\n", len(plan.PasswordPolicy)))

	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	sb.WriteString("2. RÉSULTATS PAR EMPLOYÉ\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("  %s (%s) — %.0f/100 %s\n", r.Name, r.Role, r.TotalRisk, r.Grade))
		sb.WriteString(fmt.Sprintf("  Phishing:%.0f  MdP:%.0f  WiFi:%.0f  Email:%.0f  USB:%.0f\n\n",
			r.Phishing, r.Password, r.WiFi, r.Email, r.USB))
	}

	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	sb.WriteString("3. ACTIONS PAR EMPLOYÉ\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n\n")
	for _, ea := range plan.Actions {
		if len(ea.Actions) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s — %s (%.0f/100)\n", ea.Name, ea.Role, ea.Risk))
		for _, a := range ea.Actions {
			sb.WriteString(fmt.Sprintf("    [%s] %s\n    → %s\n    Délai: %s\n\n",
				a.ISOControl, a.Title, a.Description, a.Deadline))
		}
	}

	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	sb.WriteString("4. ACTIONS GLOBALES\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n\n")
	for _, a := range plan.GlobalActions {
		sb.WriteString(fmt.Sprintf("  %d. [%s] %s\n     %s\n     Délai: %s\n\n",
			a.Priority, a.ISOControl, a.Title, a.Description, a.Deadline))
	}

	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	sb.WriteString("5. PROGRAMME DE FORMATION\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n\n")
	sb.WriteString("  Module 1 — Sécurité données patients (2h)\n")
	sb.WriteString("  Module 2 — Reconnaissance phishing (1h30)\n")
	sb.WriteString("  Module 3 — Hygiène numérique (1h)\n")
	sb.WriteString("  Module 4 — Simulation phishing (J+30)\n\n")

	sb.WriteString("  Objectifs à 90 jours:\n")
	sb.WriteString("  • Taux de clic phishing < 5%\n")
	sb.WriteString("  • Score de risque moyen < 40/100\n")
	sb.WriteString("  • 100% du personnel formé\n\n")

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("  Document confidentiel — Securthy DZ\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	return sb.String()
}
