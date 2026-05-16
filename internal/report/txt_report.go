package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"go-scanner/internal/crypto"
)

type FindingSummary struct {
	IP          string
	Grade       string
	TotalScore  int
	OpenPorts   []string
	Criticals   []string
	Highs       []string
	SMB         string
	RDP         string
	SNMP        string
	Fingerprint string
}

type EmployeeSummary struct {
	Name      string
	Role      string
	Risk      float64
	Grade     string
	Phishing  float64
	Password  float64
	WiFi      float64
	Email     float64
	Privilege float64
}

type TXTReportData struct {
	Target          string
	ScanDate        string
	NetworkHosts    []FindingSummary
	Employees       []EmployeeSummary
	ISOScore        int
	ISOGrade        string
	EmployeeAvgRisk float64
	CombinedScore   int
	CombinedGrade   string
	PackTier        string
	TotalCriticals  int
	TotalHighs      int
}

// GenerateTXT generates a human-readable TXT report AND
// an encrypted .sec version only the platform can read.
func GenerateTXT(data TXTReportData, outputPath string) error {
	content := buildReportContent(data)

	// Write plain TXT (for the technician on-site)
	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return err
	}

	// Write encrypted .sec (for the platform — unreadable by client)
	secPath := strings.TrimSuffix(outputPath, ".txt") + ".sec"
	encrypted, err := crypto.EncryptReport([]byte(content))
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	if err := os.WriteFile(secPath, encrypted, 0644); err != nil {
		return err
	}

	return nil
}

func buildReportContent(data TXTReportData) string {
	var sb strings.Builder

	line   := func(s string) { sb.WriteString(s + "\n") }
	blank  := func()         { sb.WriteString("\n") }
	sep    := func()         { line(strings.Repeat("-", 64)) }
	bigSep := func()         { line(strings.Repeat("=", 64)) }

	bigSep()
	line("  SECURTHY -- RAPPORT DE SECURITE RESEAU")
	line("  Healthcare Network Security Assessment")
	bigSep()
	blank()
	line(fmt.Sprintf("  Cible scannee  : %s", data.Target))
	line(fmt.Sprintf("  Date du scan   : %s", data.ScanDate))
	line("  Genere par     : Securthy Platform v1.0")
	blank()

	// ── Executive summary ─────────────────────────────────────────────────────
	sep()
	line("  RESUME EXECUTIF")
	sep()
	blank()
	line(fmt.Sprintf("  Score ISO 27001 reseau   : %d / 100  --  %s", data.ISOScore, data.ISOGrade))
	if data.EmployeeAvgRisk > 0 {
		line(fmt.Sprintf("  Risque employes moyen    : %.0f / 100", data.EmployeeAvgRisk))
	}
	line(fmt.Sprintf("  Score combine            : %d / 100  --  %s", data.CombinedScore, data.CombinedGrade))
	line(fmt.Sprintf("  Pack recommande          : %s", strings.ToUpper(data.PackTier)))
	blank()
	line(fmt.Sprintf("  Vulnerabilites CRITIQUES : %d", data.TotalCriticals))
	line(fmt.Sprintf("  Vulnerabilites ELEVEES   : %d", data.TotalHighs))
	line(fmt.Sprintf("  Hotes analyses           : %d", len(data.NetworkHosts)))
	blank()

	switch {
	case data.CombinedScore < 35:
		line("  [!!!] ETAT CRITIQUE -- Reseau activement expose aux ransomwares,")
		line("        vol de donnees patients et acces non autorise au DEM.")
		line("        Action immediate requise.")
	case data.CombinedScore < 60:
		line("  [!] RISQUE ELEVE -- Vulnerabilites significatives detectees.")
		line("      Conformite ISO 27001 incomplete. Correctifs requis sous 30 jours.")
	case data.CombinedScore < 80:
		line("  [i] RISQUE MODERE -- Posture acceptable mais ameliorations requises.")
	default:
		line("  [OK] POSTURE CORRECTE -- Principaux controles ISO 27001 respectes.")
	}
	blank()

	// ── Network findings ──────────────────────────────────────────────────────
	if len(data.NetworkHosts) > 0 {
		sep()
		line("  RESULTATS PAR HOTE RESEAU")
		sep()
		blank()
		for _, host := range data.NetworkHosts {
			line(fmt.Sprintf("  +-- Hote : %s", host.IP))
			line(fmt.Sprintf("  |   Score : %d  |  Grade : %s", host.TotalScore, host.Grade))
			if host.Fingerprint != "" && host.Fingerprint != " " {
				line(fmt.Sprintf("  |   Appareil : %s", host.Fingerprint))
			}
			if len(host.OpenPorts) > 0 {
				line(fmt.Sprintf("  |   Ports ouverts : %s", strings.Join(host.OpenPorts, ", ")))
			}
			if host.SMB != "" {
				line(fmt.Sprintf("  |   SMB  : %s", host.SMB))
			}
			if host.RDP != "" {
				line(fmt.Sprintf("  |   RDP  : %s", host.RDP))
			}
			if host.SNMP != "" {
				line(fmt.Sprintf("  |   SNMP : %s", host.SNMP))
			}
			if len(host.Criticals) > 0 {
				line("  |")
				line("  |   [!!!] CRITIQUE :")
				for _, c := range host.Criticals {
					line(fmt.Sprintf("  |     - %s", c))
				}
			}
			if len(host.Highs) > 0 {
				line("  |")
				line("  |   [!] ELEVE :")
				for _, h := range host.Highs {
					line(fmt.Sprintf("  |     - %s", h))
				}
			}
			line("  +" + strings.Repeat("-", 54))
			blank()
		}
	}

	// ── Employee findings ─────────────────────────────────────────────────────
	if len(data.Employees) > 0 {
		sep()
		line("  RESULTATS PAR EMPLOYE")
		sep()
		blank()
		for _, emp := range data.Employees {
			line(fmt.Sprintf("  +-- %s  (%s)", emp.Name, emp.Role))
			line(fmt.Sprintf("  |   Risque : %.0f/100  --  %s", emp.Risk, emp.Grade))
			line(fmt.Sprintf("  |   Phishing:%.0f  MdP:%.0f  WiFi:%.0f  Email:%.0f  Priv:%.0f",
				emp.Phishing, emp.Password, emp.WiFi, emp.Email, emp.Privilege))
			line("  +" + strings.Repeat("-", 54))
			blank()
		}
	}

	// ── ISO controls ──────────────────────────────────────────────────────────
	sep()
	line("  CONTROLES ISO 27001 EVALUES")
	sep()
	blank()
	line("  A.9  -- Controle d'acces        : credentials, FHIR, RDP NLA, SNMP")
	line("  A.10 -- Cryptographie            : TLS sur DICOM/HL7, certificats")
	line("  A.12 -- Securite operationnelle  : SMBv1, OS obsoletes, Modbus, SSH")
	line("  A.13 -- Securite reseau          : VLAN, SMB signing, Telnet, DB")
	line("  A.14 -- Acquisition systemes     : FHIR sans auth, DICOM sans TLS")
	blank()
	line(fmt.Sprintf("  Score global : %d/100  --  %s", data.ISOScore, data.ISOGrade))
	blank()

	// ── Pack recommendation ───────────────────────────────────────────────────
	sep()
	line("  PACK RECOMMANDE -- " + strings.ToUpper(data.PackTier))
	sep()
	blank()

	switch {
	case strings.Contains(strings.ToLower(data.PackTier), "essentiel"):
		line("  Pack Essentiel  (150 000 - 250 000 DZD  |  3-5 jours)")
		blank()
		line("  Correctifs inclus :")
		line("    1. Desactivation SMBv1  (vecteur WannaCry / EternalBlue)")
		line("    2. Activation NLA sur RDP  (protection BlueKeep)")
		line("    3. Remplacement credentials par defaut")
		line("    4. Migration Telnet vers SSH")
		line("    5. Regles firewall de base")
		blank()
		line(fmt.Sprintf("  Score attendu apres pack : %d -> %d / 100",
			data.ISOScore, clamp(data.ISOScore+27)))
	case strings.Contains(strings.ToLower(data.PackTier), "securite"):
		line("  Pack Securite  (400 000 - 600 000 DZD  |  3-4 semaines)")
		blank()
		line("  Correctifs inclus :")
		line("    1. Tout le Pack Essentiel")
		line("    2. Segmentation VLAN")
		line("    3. Passerelle TLS pour DICOM")
		line("    4. Tunnel TLS pour HL7/MLLP")
		line("    5. Authentification OAuth2/SMART sur API FHIR DEM")
		line("    6. Signature SMB forcee")
		line("    7. Upgrade SNMPv3")
		blank()
		line(fmt.Sprintf("  Score attendu apres pack : %d -> %d / 100",
			data.ISOScore, clamp(data.ISOScore+50)))
	default:
		line("  Pack Conformite  (1 000 000 - 1 500 000 DZD  |  2-3 mois)")
		blank()
		line("  Correctifs inclus :")
		line("    1. Tout le Pack Securite")
		line("    2. Architecture securite DEM complete")
		line("    3. Plan de reponse aux incidents")
		line("    4. Formation cybersecurite personnel")
		line("    5. Rapport officiel Ministere de la Sante")
		line("    6. Contrat SLA 12 mois + 4 scans trimestriels")
		blank()
		line(fmt.Sprintf("  Score attendu apres pack : %d -> %d / 100",
			data.ISOScore, clamp(data.ISOScore+67)))
	}
	blank()

	// ── Next steps ────────────────────────────────────────────────────────────
	sep()
	line("  PROCHAINES ETAPES")
	sep()
	blank()
	line("  1. Examiner les vulnerabilites CRITIQUES listees ci-dessus")
	line("  2. Contacter Securthy pour activation du pack recommande")
	line("  3. Appliquer les correctifs selon le plan de remediation")
	line("  4. Re-scanner dans 30 jours pour valider les corrections")
	blank()

	bigSep()
	line("  Document confidentiel -- usage interne uniquement")
	line("  Securthy -- Healthcare Security Platform")
	line(fmt.Sprintf("  Genere le %s", time.Now().Format("02 January 2006 15:04")))
	bigSep()

	return sb.String()
}

func clamp(n int) int {
	if n > 100 {
		return 100
	}
	return n
}
