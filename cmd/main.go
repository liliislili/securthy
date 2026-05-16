package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-scanner/internal/human"
	"go-scanner/internal/human/iso"
	"go-scanner/internal/report"
	"go-scanner/internal/scanner"
	"go-scanner/internal/scoring"
)

// ── Build-time variables (set via -ldflags at build time) ────────────────────
// go build -ldflags "-X main.PlatformURL=https://app.securthy.dz -X main.ClientAPIKey=KEY" ./cmd/
var (
	PlatformURL  = "http://localhost:8000" // default for dev
	ClientAPIKey = ""                       // set per client at build time
)

var healthcarePorts = []int{
	104, 2575, 11112,
	22, 23, 3389,
	80, 443, 8080, 8443,
	445, 139, 21,
	3306, 5432, 1433, 27017,
	135, 137,
	25, 110, 143,
	161, 502,
}

type PortReport struct {
	Port      int                `json:"port"`
	Protocol  string             `json:"protocol"`
	Service   string             `json:"service"`
	Banner    string             `json:"banner,omitempty"`
	Version   string             `json:"version,omitempty"`
	RiskLevel string             `json:"risk_level"`
	RiskScore int                `json:"risk_score"`
	CVEs      []scanner.CVE      `json:"cves,omitempty"`
	TLS       *scanner.TLSResult `json:"tls,omitempty"`
	Findings  []string           `json:"findings,omitempty"`
}

type HostReport struct {
	IP          string              `json:"ip"`
	Alive       bool                `json:"alive"`
	Fingerprint scanner.Fingerprint `json:"fingerprint"`
	Ports       []PortReport        `json:"ports"`
	UDP         []scanner.UDPResult `json:"udp,omitempty"`
	SMB         *scanner.SMBResult  `json:"smb,omitempty"`
	RDP         *scanner.RDPResult  `json:"rdp,omitempty"`
	SNMP        *scanner.SNMPResult `json:"snmp,omitempty"`
	VLAN        *scanner.VLANResult `json:"vlan,omitempty"`
	AllFindings []string            `json:"all_findings"`
	TotalScore  int                 `json:"total_risk_score"`
	Grade       string              `json:"grade"`
}

type PackTargets struct {
	Windows         []string `json:"windows"`
	Linux           []string `json:"linux"`
	RecommendedTier string   `json:"recommended_tier"`
	ISOScore        int      `json:"iso_score"`
	ISOGrade        string   `json:"iso_grade"`
}

func main() {
	target := "127.0.0.1"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	employeesFile := "employees.json"
	for _, arg := range os.Args[2:] {
		if strings.HasPrefix(arg, "--employees=") {
			employeesFile = strings.TrimPrefix(arg, "--employees=")
		}
	}

	var ips []string
	if strings.Contains(target, "/") {
		var err error
		ips, err = expandCIDR(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid CIDR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Scanning %d hosts in %s\n", len(ips), target)
	} else {
		ips = []string{target}
		fmt.Printf("[*] Scanning host: %s\n", target)
	}

	fmt.Println("[*] Healthcare security assessment — all checks enabled")
	fmt.Println(strings.Repeat("=", 60))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// ── Host discovery (parallel, 50 goroutines) ──────────────────────────────
	fmt.Printf("[*] Discovering live hosts...\n")
	var mu sync.Mutex
	var allIPs []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if isAlive(ipAddr) {
				mu.Lock()
				allIPs = append(allIPs, ipAddr)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	fmt.Printf("[*] %d/%d hosts alive\n\n", len(allIPs), len(ips))

	// ── Scan hosts (parallel, 10 at a time) ───────────────────────────────────
	hostResults := make([]HostReport, len(allIPs))
	var wg2 sync.WaitGroup
	sem2 := make(chan struct{}, 10)

	for i, ip := range allIPs {
		wg2.Add(1)
		go func(idx int, ipAddr string) {
			defer wg2.Done()
			sem2 <- struct{}{}
			defer func() { <-sem2 }()
			hostResults[idx] = assessHost(ctx, ipAddr, allIPs)
		}(i, ip)
	}
	wg2.Wait()

	var allHosts []HostReport
	for _, r := range hostResults {
		if r.IP != "" {
			allHosts = append(allHosts, r)
			printHostReport(r)
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))

	if len(allIPs) > 1 {
		var vlanResults []scanner.VLANResult
		for _, h := range allHosts {
			if h.VLAN != nil {
				vlanResults = append(vlanResults, *h.VLAN)
			}
		}
		fmt.Println("[VLAN] " + scanner.VLANSummary(vlanResults))
	}

	if len(allHosts) == 0 {
		fmt.Println("No hosts found. Is the simulator running?")
		return
	}

	// ── ISO scoring ───────────────────────────────────────────────────────────
	var allFindings []string
	smbV1, smbNoSign, rdpNoNLA, snmpVuln := false, false, false, false

	for _, h := range allHosts {
		allFindings = append(allFindings, h.AllFindings...)
		if h.SMB != nil {
			if h.SMB.SMBv1 {
				smbV1 = true
			}
			if !h.SMB.SigningRequired {
				smbNoSign = true
			}
		}
		if h.RDP != nil && !h.RDP.NLAEnabled {
			rdpNoNLA = true
		}
		if h.SNMP != nil && h.SNMP.Vulnerable {
			snmpVuln = true
		}
	}

	findings := scoring.ParseFindings(allFindings, true, smbV1, !smbNoSign, true, !rdpNoNLA, snmpVuln)
	isoReport := scoring.CalculateISO(findings)
	scoring.PrettyPrint(isoReport)

	// ── Employee scan (parallel) ──────────────────────────────────────────────
	var employeeResults []human.HumanScanResult
	employeeAvgRisk := 0.0

	if _, err := os.Stat(employeesFile); err == nil {
		fmt.Println("\n" + strings.Repeat("=", 60))
		fmt.Printf("[*] Employee scan from %s\n", employeesFile)
		fmt.Println(strings.Repeat("-", 60))

		targets, err := loadEmployees(employeesFile)
		if err == nil && len(targets) > 0 {
			empResults := make([]human.HumanScanResult, len(targets))
			var wg3 sync.WaitGroup
			for i, t := range targets {
				wg3.Add(1)
				go func(idx int, target human.EmployeeTarget) {
					defer wg3.Done()
					empResults[idx] = human.RunHumanScan(target)
				}(i, t)
			}
			wg3.Wait()

			for _, r := range empResults {
				if r.EmployeeID != "" {
					employeeResults = append(employeeResults, r)
					fmt.Printf("  [%s] %-25s risk=%.0f/100 — %s\n",
						r.Role, r.Name, r.TotalRisk, r.Grade)
					fmt.Printf("       Phishing:%.0f  Password:%.0f  WiFi:%.0f  Email:%.0f  Priv:%.0f\n",
						r.Phishing, r.Password, r.WiFi, r.Email, r.Privilege)
				}
			}

			total := 0.0
			for _, r := range employeeResults {
				total += r.TotalRisk
			}
			employeeAvgRisk = total / float64(len(employeeResults))
			fmt.Printf("\n  Employee average risk: %.0f/100\n", employeeAvgRisk)

			humanISO := buildHumanISO(employeeResults)
			fmt.Println("\n  ISO 27001 Human Controls:")
			for _, c := range humanISO.Controls {
				status := "✓"
				if !c.Passed {
					status = "✗"
				}
				fmt.Printf("  [%s] %-10s source:%-12s risk:%.0f\n",
					status, c.ControlID, c.Source, c.RiskScore)
			}
		}
	} else {
		fmt.Printf("\n[*] No %s found — skipping employee scan\n", employeesFile)
	}

	// ── Combined score ────────────────────────────────────────────────────────
	combined := scoring.CalculateCombined(isoReport.Overall, employeeAvgRisk)
	scoring.PrettyPrintCombined(combined)

	// ── targets.json for pack engine ──────────────────────────────────────────
	packTargets := PackTargets{
		RecommendedTier: isoReport.PackTier,
		ISOScore:        isoReport.Overall,
		ISOGrade:        isoReport.Grade,
	}
	for _, h := range allHosts {
		if strings.Contains(strings.ToLower(h.Fingerprint.OS), "windows") {
			packTargets.Windows = append(packTargets.Windows, h.IP)
		} else {
			packTargets.Linux = append(packTargets.Linux, h.IP)
		}
	}
	targetsData, _ := json.MarshalIndent(packTargets, "", "  ")
	os.WriteFile("targets.json", targetsData, 0644)

	// ── Generate reports ──────────────────────────────────────────────────────
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	// Full JSON report
	fullReport := map[string]interface{}{
		"timestamp":         time.Now().Format(time.RFC3339),
		"target":            target,
		"network_hosts":     allHosts,
		"employees":         employeeResults,
		"iso_score":         isoReport.Overall,
		"iso_score_before":  isoReport.Overall,
		"iso_grade":         isoReport.Grade,
		"employee_avg_risk": employeeAvgRisk,
		"combined_score":    combined.CombinedScore,
		"combined_grade":    combined.CombinedGrade,
		"recommended_pack":  isoReport.PackTier,
		"total_criticals":   countPrefix(allFindings, "CRITICAL"),
		"total_highs":       countPrefix(allFindings, "HIGH"),
	}
	jsonData, _ := json.MarshalIndent(fullReport, "", "  ")
	jsonPath := "report_" + ts + ".json"
	os.WriteFile(jsonPath, jsonData, 0644)

	// TXT + encrypted .sec
	txtData := buildTXTData(target, isoReport, combined, allHosts,
		employeeResults, employeeAvgRisk, allFindings)

	txtPath := "report_" + ts + ".txt"
	secPath := "report_" + ts + ".sec"

	if err := report.GenerateTXT(txtData, txtPath); err != nil {
		fmt.Println("[!] TXT/SEC report failed:", err)
	}

	// ── Summary ───────────────────────────────────────────────────────────────
	fmt.Printf("\n[+] ISO Score      : %d/100 — %s\n", isoReport.Overall, isoReport.Grade)
	fmt.Printf("[+] Combined Score : %d/100 — %s\n", combined.CombinedScore, combined.CombinedGrade)
	fmt.Printf("[+] Pack tier      : %s\n", strings.ToUpper(isoReport.PackTier))
	fmt.Printf("[+] JSON report    : %s\n", jsonPath)
	fmt.Printf("[+] TXT report     : %s\n", txtPath)
	fmt.Printf("[+] SEC report     : %s (encrypted)\n", secPath)
	fmt.Printf("[+] targets.json   : ready for pack engine\n")

	// ── Send to platform ──────────────────────────────────────────────────────
	sendReportToPlatform(secPath, jsonData)

	fmt.Printf("\n[*] Next step:\n")
	fmt.Printf("    ./packs_bin --targets=targets.json --ssh-key=~/.ssh/id_rsa\n")
	fmt.Printf("\nScan complete — %d hosts assessed\n", len(allHosts))
}

// ── Report building ───────────────────────────────────────────────────────────

func buildTXTData(
	target string,
	isoReport scoring.ISOReport,
	combined scoring.CombinedISOReport,
	allHosts []HostReport,
	employeeResults []human.HumanScanResult,
	employeeAvgRisk float64,
	allFindings []string,
) report.TXTReportData {

	txtData := report.TXTReportData{
		Target:          target,
		ScanDate:        time.Now().Format("02 January 2006 a 15:04"),
		ISOScore:        isoReport.Overall,
		ISOGrade:        isoReport.Grade,
		PackTier:        isoReport.PackTier,
		EmployeeAvgRisk: employeeAvgRisk,
		CombinedScore:   combined.CombinedScore,
		CombinedGrade:   combined.CombinedGrade,
		TotalCriticals:  countPrefix(allFindings, "CRITICAL"),
		TotalHighs:      countPrefix(allFindings, "HIGH"),
	}

	for _, e := range employeeResults {
		txtData.Employees = append(txtData.Employees, report.EmployeeSummary{
			Name: e.Name, Role: e.Role, Risk: e.TotalRisk, Grade: e.Grade,
			Phishing: e.Phishing, Password: e.Password, WiFi: e.WiFi,
			Email: e.Email, Privilege: e.Privilege,
		})
	}

	for _, h := range allHosts {
		fs := report.FindingSummary{
			IP:          h.IP,
			Grade:       h.Grade,
			TotalScore:  h.TotalScore,
			Fingerprint: strings.TrimSpace(h.Fingerprint.OS + " " + h.Fingerprint.DeviceType),
		}
		for _, p := range h.Ports {
			fs.OpenPorts = append(fs.OpenPorts, fmt.Sprintf("%d/%s", p.Port, p.Service))
			for _, f := range p.Findings {
				if strings.HasPrefix(f, "CRITICAL") {
					fs.Criticals = append(fs.Criticals, f)
				} else if strings.HasPrefix(f, "HIGH") {
					fs.Highs = append(fs.Highs, f)
				}
			}
		}
		if h.SMB != nil && h.SMB.Open {
			fs.SMB = fmt.Sprintf("%s | signing_required=%v | smbv1=%v",
				h.SMB.Version, h.SMB.SigningRequired, h.SMB.SMBv1)
		}
		if h.RDP != nil && h.RDP.Open {
			fs.RDP = fmt.Sprintf("%s | NLA=%v", h.RDP.Version, h.RDP.NLAEnabled)
		}
		if h.SNMP != nil && h.SNMP.Vulnerable {
			fs.SNMP = fmt.Sprintf("vulnerable — communities: %v", h.SNMP.CommunityWorks)
		}
		txtData.NetworkHosts = append(txtData.NetworkHosts, fs)
	}

	return txtData
}

// ── Platform upload ───────────────────────────────────────────────────────────

func sendReportToPlatform(secPath string, jsonData []byte) {
	// Use env vars if set, otherwise fall back to baked-in values
	url := os.Getenv("SECURTHY_PLATFORM_URL")
	key := os.Getenv("SECURTHY_API_KEY")
	if url == "" {
		url = PlatformURL
	}
	if key == "" {
		key = ClientAPIKey
	}

	if url == "" || key == "" {
		fmt.Println("\n[*] Platform upload disabled.")
		fmt.Println("    Set SECURTHY_PLATFORM_URL and SECURTHY_API_KEY to enable.")
		return
	}

	fmt.Printf("\n[*] Uploading encrypted report to %s...\n", url)

	secData, err := os.ReadFile(secPath)
	if err != nil {
		fmt.Println("[!] Cannot read encrypted report:", err)
		return
	}

	req, err := http.NewRequest("POST",
		url+"/scan/receive-report",
		bytes.NewReader(secData))
	if err != nil {
		fmt.Println("[!] Cannot create request:", err)
		return
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-Report-Format", "securthy-v1-encrypted")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[!] Cannot reach platform:", err)
		fmt.Println("    Report saved locally — upload manually when connected.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		fmt.Println("[+] Report uploaded to platform successfully.")
		fmt.Println("    Results are now visible on the dashboard.")
	} else {
		fmt.Printf("[!] Platform returned HTTP %d\n", resp.StatusCode)
	}
}

// ── Helper functions ──────────────────────────────────────────────────────────

func countPrefix(findings []string, prefix string) int {
	n := 0
	for _, f := range findings {
		if strings.HasPrefix(f, prefix) {
			n++
		}
	}
	return n
}

func loadEmployees(path string) ([]human.EmployeeTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []human.EmployeeTarget
	return targets, json.Unmarshal(data, &targets)
}

func buildHumanISO(results []human.HumanScanResult) iso.ISOReport {
	if len(results) == 0 {
		return iso.ISOReport{}
	}
	avg := func(f func(human.HumanScanResult) float64) float64 {
		t := 0.0
		for _, r := range results {
			t += f(r)
		}
		return t / float64(len(results))
	}
	return iso.MapControls(
		avg(func(r human.HumanScanResult) float64 { return r.Phishing }),
		avg(func(r human.HumanScanResult) float64 { return r.Password }),
		avg(func(r human.HumanScanResult) float64 { return r.WiFi }),
		avg(func(r human.HumanScanResult) float64 { return r.Email }),
		avg(func(r human.HumanScanResult) float64 { return r.Session }),
		avg(func(r human.HumanScanResult) float64 { return r.Privilege }),
		avg(func(r human.HumanScanResult) float64 { return r.USB }),
		avg(func(r human.HumanScanResult) float64 { return r.Browser }),
		avg(func(r human.HumanScanResult) float64 { return r.Data }),
	)
}

func assessHost(ctx context.Context, ip string, allIPs []string) HostReport {
	r := HostReport{IP: ip, Alive: true}
	var allFindings []string

	openPorts := discoverOpenPorts(ctx, ip, healthcarePorts)
	banners := map[int]string{}

	for _, port := range openPorts {
		pr := PortReport{Port: port, Protocol: "tcp", RiskLevel: "LOW"}
		var portFindings []string

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
		if err == nil {
			func() {
				defer conn.Close()
				probe := scanner.ProbeService(port, conn)
				sr := scanner.BuildReport(ip, port, probe.Service, probe.Banner)
				pr.Service = sr.Service
				pr.Banner = sr.Banner
				pr.Version = sr.Version
				pr.RiskLevel = string(sr.Risk.Level)
				pr.RiskScore = sr.Risk.Score
				pr.CVEs = sr.Risk.CVEs
				banners[port] = probe.Banner
				for _, c := range sr.Risk.CVEs {
					portFindings = append(portFindings,
						fmt.Sprintf("[CVE-%d] %s: %s", c.Severity, c.ID, c.Description))
				}
			}()
		} else {
			pr.Service = scanner.GuessService(port)
		}

		tlsResult := scanner.CheckTLS(ip, port)
		pr.TLS = &tlsResult
		tlsF := scanner.TLSRisk(tlsResult, port)
		portFindings = append(portFindings, tlsF...)
		pr.RiskScore += len(tlsF) * 5

		switch pr.Service {
		case "ftp":
			cred := scanner.CheckDefaultFTP(ip, port)
			if cred != nil && cred.Vulnerable {
				portFindings = append(portFindings,
					fmt.Sprintf("CRITICAL: Default FTP creds work — %s / %s", cred.Username, cred.Password))
				pr.RiskScore += 30
				pr.RiskLevel = "CRITICAL"
			}
		case "http", "http-alt":
			cred := scanner.CheckDefaultHTTP(ip, port)
			if cred != nil && cred.Vulnerable {
				portFindings = append(portFindings,
					fmt.Sprintf("CRITICAL: Default HTTP creds work — %s / %s", cred.Username, cred.Password))
				pr.RiskScore += 25
				pr.RiskLevel = "CRITICAL"
			}
		}

		if pr.Service == "telnet" || port == 23 {
			telnet := scanner.CheckTelnet(ip, port)
			portFindings = append(portFindings, scanner.TelnetFindings(telnet, ip, port)...)
			if telnet.NoPassword {
				pr.RiskScore += 40
				pr.RiskLevel = "CRITICAL"
			}
		}

		if port == 80 || port == 443 || port == 8080 || port == 8443 {
			fhir := scanner.CheckFHIR(ip, port)
			portFindings = append(portFindings, scanner.FHIRFindings(fhir, ip, port)...)
			if fhir.PatientDataLeak {
				pr.RiskScore += 40
				pr.RiskLevel = "CRITICAL"
			}
		}

		pr.Findings = portFindings
		allFindings = append(allFindings, portFindings...)
		r.Ports = append(r.Ports, pr)
	}

	udpResults := scanner.ScanUDP(ip, scanner.UDPHealthcarePorts)
	r.UDP = udpResults
	allFindings = append(allFindings, scanner.UDPFindings(udpResults, ip)...)

	smb := scanner.CheckSMB(ip)
	r.SMB = &smb
	allFindings = append(allFindings, scanner.SMBFindings(smb, ip)...)

	rdp := scanner.CheckRDP(ip)
	r.RDP = &rdp
	allFindings = append(allFindings, scanner.RDPFindings(rdp, ip)...)

	snmp := scanner.CheckSNMP(ip)
	r.SNMP = &snmp
	allFindings = append(allFindings, scanner.SNMPFinding(snmp, ip)...)

	if len(allIPs) > 1 {
		vlan := scanner.TestVLANSegmentation(ip, allIPs)
		r.VLAN = &vlan
		allFindings = append(allFindings, vlan.Violations...)
	}

	r.Fingerprint = scanner.FingerprintHost(ip, banners)

	score := 0
	for _, p := range r.Ports {
		score += p.RiskScore
	}
	for _, f := range allFindings {
		switch {
		case strings.HasPrefix(f, "CRITICAL"):
			score += 15
		case strings.HasPrefix(f, "HIGH"):
			score += 8
		case strings.HasPrefix(f, "MEDIUM"):
			score += 3
		}
	}

	r.AllFindings = allFindings
	r.TotalScore = score
	r.Grade = grade(score)
	return r
}

func printHostReport(r HostReport) {
	fmt.Printf("\n[HOST] %s — Score: %d | Grade: %s\n", r.IP, r.TotalScore, r.Grade)
	fmt.Printf("  Device: %s | %s\n", r.Fingerprint.OS, r.Fingerprint.DeviceType)

	for _, p := range r.Ports {
		fmt.Printf("  TCP %-5d %-18s risk=%-8s score=%d\n",
			p.Port, p.Service, p.RiskLevel, p.RiskScore)
		for _, f := range p.Findings {
			fmt.Printf("         %s\n", f)
		}
	}
	for _, u := range r.UDP {
		fmt.Printf("  UDP %-5d %-18s %s\n", u.Port, u.Service, u.Banner)
	}
	if r.SMB != nil && r.SMB.Open {
		fmt.Printf("  SMB: %s | signing=%v | smbv1=%v\n",
			r.SMB.Version, r.SMB.SigningRequired, r.SMB.SMBv1)
	}
	if r.RDP != nil && r.RDP.Open {
		fmt.Printf("  RDP: %s | NLA=%v\n", r.RDP.Version, r.RDP.NLAEnabled)
	}
	if r.SNMP != nil && r.SNMP.Vulnerable {
		fmt.Printf("  SNMP: communities=%v\n", r.SNMP.CommunityWorks)
	}

	criticals := filterPrefix(r.AllFindings, "CRITICAL")
	highs := filterPrefix(r.AllFindings, "HIGH")
	if len(criticals)+len(highs) > 0 {
		fmt.Printf("  Findings: %d CRITICAL, %d HIGH\n", len(criticals), len(highs))
		for _, f := range criticals {
			fmt.Printf("    [!!!] %s\n", f)
		}
		for _, f := range highs {
			fmt.Printf("    [!]   %s\n", f)
		}
	}
}

func filterPrefix(findings []string, prefix string) []string {
	var out []string
	for _, f := range findings {
		if strings.HasPrefix(f, prefix) {
			out = append(out, f)
		}
	}
	return out
}

func grade(score int) string {
	switch {
	case score == 0:
		return "A — clean"
	case score < 20:
		return "B — low risk"
	case score < 50:
		return "C — moderate"
	case score < 100:
		return "D — high risk"
	default:
		return "F — CRITICAL"
	}
}

func isAlive(ip string) bool {
	for _, port := range []int{80, 22, 443, 445, 104, 3389, 23, 2575, 8080} {
		conn, err := net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", ip, port), 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func discoverOpenPorts(ctx context.Context, ip string, ports []int) []int {
	type result struct {
		port int
		open bool
	}
	ch := make(chan result, len(ports))
	for _, port := range ports {
		go func(p int) {
			select {
			case <-ctx.Done():
				ch <- result{p, false}
			default:
				conn, err := net.DialTimeout("tcp",
					fmt.Sprintf("%s:%d", ip, p), 600*time.Millisecond)
				if err == nil {
					conn.Close()
					ch <- result{p, true}
				} else {
					ch <- result{p, false}
				}
			}
		}(port)
	}
	var open []int
	for range ports {
		r := <-ch
		if r.open {
			open = append(open, r.port)
		}
	}
	return open
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
