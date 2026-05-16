package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// validLicenses maps license key → allowed tier
// In production these come from your platform API
var validLicenses = map[string]string{
	"HG-ESS-2024-DEMO": "essentiel",
	"HG-SEC-2024-DEMO": "securite",
	"HG-CON-2024-DEMO": "conformite",
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	licenseKey := ""
	targetFile := ""
	winUser := "Administrator"
	winPass := ""
	sshUser := "root"
	sshKey := ""
	sshPass := ""
	sshPort := 0

	for _, arg := range os.Args[1:] {
		switch {
		case strings.HasPrefix(arg, "--license="):
			licenseKey = strings.TrimPrefix(arg, "--license=")
		case strings.HasPrefix(arg, "--targets="):
			targetFile = strings.TrimPrefix(arg, "--targets=")
		case strings.HasPrefix(arg, "--win-user="):
			winUser = strings.TrimPrefix(arg, "--win-user=")
		case strings.HasPrefix(arg, "--win-pass="):
			winPass = strings.TrimPrefix(arg, "--win-pass=")
		case strings.HasPrefix(arg, "--ssh-user="):
			sshUser = strings.TrimPrefix(arg, "--ssh-user=")
		case strings.HasPrefix(arg, "--ssh-key="):
			sshKey = strings.TrimPrefix(arg, "--ssh-key=")
		case strings.HasPrefix(arg, "--ssh-pass="):
			sshPass = strings.TrimPrefix(arg, "--ssh-pass=")
		case strings.HasPrefix(arg, "--ssh-port="):
			sshPort, _ = strconv.Atoi(strings.TrimPrefix(arg, "--ssh-port="))
		}
	}

	// ── License validation ────────────────────────────────────────────────────
	if licenseKey == "" {
		fmt.Println()
		fmt.Println("  ┌─────────────────────────────────────────────────────┐")
		fmt.Println("  │  LICENSE KEY REQUIRED                               │")
		fmt.Println("  │                                                     │")
		fmt.Println("  │  Purchase a pack at: https://securthy-dz.com     │")
		fmt.Println("  │  Then run:                                          │")
		fmt.Println("  │  ./packs_bin --license=YOUR-KEY --targets=targets.json │")
		fmt.Println("  └─────────────────────────────────────────────────────┘")
		fmt.Println()
		os.Exit(1)
	}

	tier, valid := validateLicense(licenseKey)
	if !valid {
		fmt.Println()
		fmt.Println("  [✗] Invalid or expired license key:", licenseKey)
		fmt.Println("  Purchase a valid license at: https://securthy-dz.com")
		fmt.Println()
		os.Exit(1)
	}

	fmt.Printf("\n  [✓] License valid — Pack %s unlocked\n\n", strings.ToUpper(tier))

	// ── Load targets ──────────────────────────────────────────────────────────
	targets, err := loadTargets(targetFile)
	if err != nil {
		fmt.Println("[!] Could not load targets:", err)
		os.Exit(1)
	}

	// Warn if tier doesn't match recommended
	if targets.RecommendedTier != "" && targets.RecommendedTier != tier {
		fmt.Printf("  [!] Note: Scanner recommended '%s' but you purchased '%s'\n",
			strings.ToUpper(targets.RecommendedTier), strings.ToUpper(tier))
		fmt.Printf("  [!] ISO Score was %d/100 — %s\n\n",
			targets.ISOScore, targets.ISOGrade)
	}

	printBanner(tier, targets)

	winCreds := WinCreds{User: winUser, Pass: winPass}
	sshCreds := SSHCreds{User: sshUser, KeyPath: sshKey, Port: sshPort, Pass: sshPass}

	log := NewRunLog()

	switch strings.ToLower(tier) {
	case "essentiel":
		RunEssentiel(targets, winCreds, sshCreds, log)
	case "securite":
		RunSecurite(targets, winCreds, sshCreds, log)
	case "conformite":
		RunConformite(targets, winCreds, sshCreds, log)
	default:
		fmt.Println("[!] Unknown tier:", tier)
		os.Exit(1)
	}

	log.PrintSummary()
	log.SaveReport(fmt.Sprintf("pack_report_%d.json", time.Now().Unix()))
}

// validateLicense checks the key and returns the tier it unlocks
func validateLicense(key string) (string, bool) {
	// Check hardcoded demo keys first
	if tier, ok := validLicenses[key]; ok {
		return tier, true
	}

	// In production: call your platform API to validate
	// tier, valid := callPlatformAPI(key)

	// For now: validate format HG-XXX-YYYY-XXXXX and derive tier
	parts := strings.Split(key, "-")
	if len(parts) != 4 || parts[0] != "HG" {
		return "", false
	}

	// Verify checksum (last part must match hash of first 3 parts)
	checksum := fmt.Sprintf("%X", sha256.Sum256([]byte(strings.Join(parts[:3], "-"))))[:5]
	if parts[3] != checksum {
		return "", false
	}

	switch strings.ToUpper(parts[1]) {
	case "ESS":
		return "essentiel", true
	case "SEC":
		return "securite", true
	case "CON":
		return "conformite", true
	}

	return "", false
}

func printBanner(tier string, targets *Targets) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Printf("║   Securthy DZ — Pack %-30s      ║\n", strings.ToUpper(tier))
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║   Windows hosts : %-5d                                  ║\n", len(targets.Windows))
	fmt.Printf("║   Linux hosts   : %-5d                                  ║\n", len(targets.Linux))
	if targets.ISOScore > 0 {
		fmt.Printf("║   ISO Score     : %-3d/100 — %-28s  ║\n", targets.ISOScore, targets.ISOGrade)
	}
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("  WARNING: This will modify system configurations.")
	fmt.Println("  Ensure you have written authorization from the client.")
	fmt.Println()
	fmt.Print("  Continue? [y/N]: ")
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) != "y" {
		fmt.Println("Aborted.")
		os.Exit(0)
	}
	fmt.Println()
}

func printUsage() {
	fmt.Println(`
Securthy DZ — Remediation Pack Engine

Usage:
  ./packs_bin --license=YOUR-LICENSE-KEY --targets=targets.json --ssh-key=~/.ssh/id_rsa

Flags:
  --license=     License key from securthy-dz.com (required)
  --targets=     Path to targets.json (generated by scanner)
  --win-user=    Windows admin username (default: Administrator)
  --win-pass=    Windows admin password
  --ssh-user=    Linux SSH username (default: root)
  --ssh-key=     Path to SSH private key
  --ssh-pass=    SSH password (alternative to key)
  --ssh-port=    SSH port (default: 22)

Demo license keys:
  Pack Essentiel  : HG-ESS-2024-DEMO
  Pack Sécurité   : HG-SEC-2024-DEMO
  Pack Conformité : HG-CON-2024-DEMO
`)
}
