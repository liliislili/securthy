package scoring

import "fmt"

type Fix struct {
	Title       string
	Description string
	ISOControl  string
	Effort      string // "1 hour", "1 day", "1 week"
	Priority    int    // 1 = do first
}

type Pack struct {
	Tier          string
	NameFR        string
	NameAR        string
	Description   string
	Fixes         []Fix
	CurrentScore  int
	ExpectedScore int
	PriceRange    string
	Duration      string // implementation time
}

// BuildPack takes the ISO report and returns the recommended pack
func BuildPack(report ISOReport) Pack {
	switch report.PackTier {
	case "conformite":
		return buildConformite(report)
	case "securite":
		return buildSecurite(report)
	default:
		return buildEssentiel(report)
	}
}

// BuildAllPacks returns all three packs for comparison
func BuildAllPacks(report ISOReport) []Pack {
	base := buildEssentiel(report)
	mid := buildSecurite(report)
	full := buildConformite(report)
	return []Pack{base, mid, full}
}

func buildEssentiel(r ISOReport) Pack {
	p := Pack{
		Tier:          "essentiel",
		NameFR:        "Pack Essentiel",
		NameAR:        "الحزمة الأساسية",
		Description:   "Corrections immédiates des expositions critiques. Réduit le risque de ransomware de 70%.",
		CurrentScore:  r.Overall,
		ExpectedScore: clamp(r.Overall + 27),
		PriceRange:    "150 000 – 250 000 DZD",
		Duration:      "3–5 jours",
	}

	// Always include these regardless of findings
	p.Fixes = []Fix{
		{
			Title:       "Désactivation de SMBv1",
			Description: "Désactiver le protocole SMBv1 sur tous les postes Windows via Group Policy. Élimine le vecteur WannaCry/EternalBlue.",
			ISOControl:  "A.12.6.1",
			Effort:      "2 heures",
			Priority:    1,
		},
		{
			Title:       "Activation de NLA sur RDP",
			Description: "Forcer Network Level Authentication sur tous les bureaux distants. Bloque les attaques pre-authentication.",
			ISOControl:  "A.9.4.2",
			Effort:      "1 heure",
			Priority:    1,
		},
		{
			Title:       "Remplacement des credentials par défaut",
			Description: "Changer tous les mots de passe par défaut: PACS, FTP, routeurs, switches. Implémenter une politique de mots de passe forts.",
			ISOControl:  "A.9.4.3",
			Effort:      "4 heures",
			Priority:    1,
		},
		{
			Title:       "Désactivation de Telnet → SSH",
			Description: "Désactiver Telnet sur tous les équipements réseau. Configurer SSH avec authentification par clé.",
			ISOControl:  "A.13.2.1",
			Effort:      "3 heures",
			Priority:    2,
		},
		{
			Title:       "Règles firewall de base",
			Description: "Bloquer les ports de base de données (3306, 1433, 27017) depuis l'extérieur. Fermer les ports inutilisés.",
			ISOControl:  "A.13.1.1",
			Effort:      "4 heures",
			Priority:    2,
		},
		{
			Title:       "Rapport d'audit PDF",
			Description: "Rapport complet des vulnérabilités trouvées, score ISO 27001, et plan de remédiation.",
			ISOControl:  "A.18.2.2",
			Effort:      "inclus",
			Priority:    3,
		},
	}

	return p
}

func buildSecurite(r ISOReport) Pack {
	p := Pack{
		Tier:          "securite",
		NameFR:        "Pack Sécurité",
		NameAR:        "حزمة الأمان",
		Description:   "Architecture sécurisée complète. Conformité ISO 27001 partielle. Protection des données patients (DEM/DICOM/HL7).",
		CurrentScore:  r.Overall,
		ExpectedScore: clamp(r.Overall + 50),
		PriceRange:    "400 000 – 600 000 DZD",
		Duration:      "3–4 semaines",
	}

	// Includes everything from Essentiel + more
	p.Fixes = append(buildEssentiel(r).Fixes, []Fix{
		{
			Title:       "Segmentation VLAN",
			Description: "Conception et déploiement de 4 VLANs: médical (DICOM/HL7), clinique (postes médecins), administratif, invités. Règles inter-VLAN via firewall.",
			ISOControl:  "A.13.1.3",
			Effort:      "1 semaine",
			Priority:    1,
		},
		{
			Title:       "Chiffrement TLS pour DICOM",
			Description: "Déploiement d'une passerelle TLS devant le serveur PACS. Toutes les transmissions d'imagerie médicale chiffrées en transit.",
			ISOControl:  "A.10.1.1",
			Effort:      "3 jours",
			Priority:    1,
		},
		{
			Title:       "Chiffrement TLS pour HL7/MLLP",
			Description: "Tunnel TLS sur toutes les connexions HL7 entre le DEM, le laboratoire et les systèmes d'imagerie.",
			ISOControl:  "A.10.1.1",
			Effort:      "2 jours",
			Priority:    1,
		},
		{
			Title:       "Authentification API FHIR (DEM)",
			Description: "Implémentation OAuth2/SMART on FHIR sur le serveur DEM. Aucun dossier patient accessible sans token valide.",
			ISOControl:  "A.9.4.1",
			Effort:      "5 jours",
			Priority:    1,
		},
		{
			Title:       "Activation signature SMB",
			Description: "Forcer SMB signing sur tous les postes Windows via Group Policy. Bloque les attaques NTLM relay.",
			ISOControl:  "A.13.1.1",
			Effort:      "2 heures",
			Priority:    2,
		},
		{
			Title:       "Sécurisation SNMP v3",
			Description: "Remplacer SNMP v1/v2 community 'public' par SNMPv3 avec authentification SHA et chiffrement AES.",
			ISOControl:  "A.9.1.2",
			Effort:      "1 jour",
			Priority:    2,
		},
		{
			Title:       "Rapport ISO 27001 — état des lieux",
			Description: "Rapport complet de conformité ISO 27001 avec score par domaine, plan de remédiation priorisé, et feuille de route 12 mois.",
			ISOControl:  "A.18.2.2",
			Effort:      "inclus",
			Priority:    3,
		},
		{
			Title:       "Scan de suivi (3 mois)",
			Description: "Re-scan complet du réseau 3 mois après implémentation pour valider les corrections et détecter de nouvelles expositions.",
			ISOControl:  "A.12.7.1",
			Effort:      "inclus",
			Priority:    3,
		},
	}...)

	return p
}

func buildConformite(r ISOReport) Pack {
	p := Pack{
		Tier:          "conformite",
		NameFR:        "Pack Conformité",
		NameAR:        "حزمة الامتثال",
		Description:   "Mise en conformité complète ISO 27001. Rapport ministère. Contrat annuel de surveillance et de remédiation continue.",
		CurrentScore:  r.Overall,
		ExpectedScore: clamp(r.Overall + 67),
		PriceRange:    "1 000 000 – 1 500 000 DZD",
		Duration:      "2–3 mois",
	}

	// All fixes from Sécurité + full compliance layer
	p.Fixes = append(buildSecurite(r).Fixes, []Fix{
		{
			Title:       "Architecture sécurité DEM complète",
			Description: "Audit complet de l'architecture DEM (Dossier Médical Électronique): FHIR R4, API gateway, journalisation, conformité CNAS/MSPRH.",
			ISOControl:  "A.14.2.5",
			Effort:      "2 semaines",
			Priority:    1,
		},
		{
			Title:       "Plan de réponse aux incidents",
			Description: "Procédures documentées pour les incidents de sécurité: ransomware, fuite de données, intrusion. Exercices de simulation.",
			ISOControl:  "A.16.1.5",
			Effort:      "1 semaine",
			Priority:    2,
		},
		{
			Title:       "Formation sécurité du personnel",
			Description: "Formation cybersécurité pour médecins, infirmiers et personnel administratif. Focus: phishing, mots de passe, données patients.",
			ISOControl:  "A.7.2.2",
			Effort:      "2 jours",
			Priority:    2,
		},
		{
			Title:       "Isolation des équipements médicaux legacy",
			Description: "Dispositifs médicaux sous Windows XP/7 isolés dans un VLAN dédié avec règles de pare-feu strictes et micro-segmentation.",
			ISOControl:  "A.12.6.1",
			Effort:      "1 semaine",
			Priority:    1,
		},
		{
			Title:       "Rapport de conformité ministère",
			Description: "Rapport officiel destiné au Ministère de la Santé: état de conformité, preuves techniques, plan d'amélioration continue.",
			ISOControl:  "A.18.1.1",
			Effort:      "inclus",
			Priority:    3,
		},
		{
			Title:       "Scans trimestriels (contrat 12 mois)",
			Description: "4 scans de sécurité complets par an avec rapport ISO mis à jour. SLA de réponse aux incidents critiques sous 4h.",
			ISOControl:  "A.12.7.1",
			Effort:      "inclus",
			Priority:    3,
		},
	}...)

	return p
}

// PrintPack prints a pack summary to terminal
func PrintPack(p Pack) {
	fmt.Printf("\n╔══ %s (%s) ══\n", p.NameFR, p.NameAR)
	fmt.Printf("║  %s\n", p.Description)
	fmt.Printf("║  Score: %d → %d  |  Prix: %s  |  Durée: %s\n",
		p.CurrentScore, p.ExpectedScore, p.PriceRange, p.Duration)
	fmt.Printf("║  Corrections incluses (%d):\n", len(p.Fixes))
	for i, fix := range p.Fixes {
		fmt.Printf("║  %d. [%s] %s (%s)\n", i+1, fix.ISOControl, fix.Title, fix.Effort)
	}
	fmt.Println("╚" + fmt.Sprintf("%s", repeatStr("═", 50)))
}

func clamp(n int) int {
	if n > 95 {
		return 95
	}
	return n
}

func repeatStr(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
