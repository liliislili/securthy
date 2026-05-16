package behavior

import (
	"fmt"
	"os/exec"
	"strings"
)

type WiFiNetwork struct {
	SSID       string
	BSSID      string
	Security   string // WPA3, WPA2, WEP, Open
	Signal     int
	Vulnerable bool
	Finding    string
}

type WiFiResult struct {
	Networks []WiFiNetwork
	HasOpen  bool
	HasWEP   bool
	HasWPA2  bool // WPA2 is acceptable but flag if WPA3 available
	HasWPA3  bool
}

// ScanWiFi uses system tools to detect nearby wireless networks
func ScanWiFi() WiFiResult {
	result := WiFiResult{}

	// Try nmcli first (most Linux systems)
	networks := scanWithNmcli()
	if len(networks) == 0 {
		// Fallback: iwlist
		networks = scanWithIwlist()
	}

	result.Networks = networks

	for _, n := range networks {
		switch {
		case n.Security == "Open" || n.Security == "--" || n.Security == "":
			result.HasOpen = true
		case strings.Contains(n.Security, "WEP"):
			result.HasWEP = true
		case strings.Contains(n.Security, "WPA3"):
			result.HasWPA3 = true
		case strings.Contains(n.Security, "WPA2") || strings.Contains(n.Security, "WPA1"):
			result.HasWPA2 = true
		}
	}

	return result
}

func scanWithNmcli() []WiFiNetwork {
	out, err := exec.Command("nmcli", "-t", "-f",
		"SSID,BSSID,SECURITY,SIGNAL", "dev", "wifi", "list").Output()
	if err != nil {
		return nil
	}

	var networks []WiFiNetwork
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		// nmcli -t separates with ":"
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}

		ssid := parts[0]
		bssid := parts[1]
		security := parts[2]
		signal := 0
		fmt.Sscanf(parts[3], "%d", &signal)

		if ssid == "" || ssid == "--" {
			continue
		}

		n := WiFiNetwork{
			SSID:     ssid,
			BSSID:    bssid,
			Security: security,
			Signal:   signal,
		}

		// Classify risk
		switch {
		case security == "" || security == "--":
			n.Security = "Open"
			n.Vulnerable = true
			n.Finding = fmt.Sprintf("CRITICAL: Open WiFi network '%s' — no encryption, any device can join and intercept traffic", ssid)
		case strings.Contains(security, "WEP"):
			n.Vulnerable = true
			n.Finding = fmt.Sprintf("CRITICAL: WEP encryption on '%s' — crackable in minutes, equivalent to no security", ssid)
		case strings.Contains(security, "WPA") && !strings.Contains(security, "WPA2") && !strings.Contains(security, "WPA3"):
			n.Vulnerable = true
			n.Finding = fmt.Sprintf("HIGH: WPA1 on '%s' — deprecated, vulnerable to TKIP attacks", ssid)
		case strings.Contains(security, "WPA2") && !strings.Contains(security, "WPA3"):
			n.Finding = fmt.Sprintf("MEDIUM: WPA2 on '%s' — acceptable but WPA3 recommended for medical networks", ssid)
		case strings.Contains(security, "WPA3"):
			n.Finding = fmt.Sprintf("OK: WPA3 on '%s' — strong encryption", ssid)
		}

		networks = append(networks, n)
	}

	return networks
}

func scanWithIwlist() []WiFiNetwork {
	out, err := exec.Command("iwlist", "scan").Output()
	if err != nil {
		return nil
	}

	var networks []WiFiNetwork
	var current WiFiNetwork
	inCell := false

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Cell") {
			if inCell && current.SSID != "" {
				networks = append(networks, current)
			}
			current = WiFiNetwork{}
			inCell = true
		}

		if strings.Contains(line, "ESSID:") {
			current.SSID = strings.Trim(strings.TrimPrefix(line, "ESSID:"), "\"")
		}
		if strings.Contains(line, "Encryption key:off") {
			current.Security = "Open"
			current.Vulnerable = true
			current.Finding = fmt.Sprintf("CRITICAL: Open WiFi '%s'", current.SSID)
		}
		if strings.Contains(line, "WPA2") {
			current.Security = "WPA2"
		}
		if strings.Contains(line, "WPA3") {
			current.Security = "WPA3"
		}
		if strings.Contains(line, "WEP") {
			current.Security = "WEP"
			current.Vulnerable = true
		}
	}

	if inCell && current.SSID != "" {
		networks = append(networks, current)
	}

	return networks
}

// WiFiFindings returns all risk findings from WiFi scan
func WiFiFindings(r WiFiResult) []string {
	var findings []string
	for _, n := range r.Networks {
		if n.Finding != "" {
			findings = append(findings, n.Finding)
		}
	}
	if r.HasOpen {
		findings = append(findings,
			"CRITICAL: Open WiFi detected — patient data can be intercepted by anyone in range")
	}
	if r.HasWEP {
		findings = append(findings,
			"CRITICAL: WEP WiFi detected — encryption crackable in under 60 seconds")
	}
	return findings
}
func Run() float64 {
	result := ScanWiFi()

	// Highest risk conditions
	if result.HasOpen || result.HasWEP {
		return 100.0
	}

	// Medium risk: only WPA2 (no WPA3 available)
	if result.HasWPA2 && !result.HasWPA3 {
		return 60.0
	}

	// Good security
	if result.HasWPA3 {
		return 20.0
	}

	// Default fallback
	return 40.0
}