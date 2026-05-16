package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ── Hospital topology ────────────────────────────────────────────────────────
//
//  Simulated Algerian hospital network — star topology
//
//  All devices bind to 127.0.0.x loopback aliases.
//  On Linux: sudo ip addr add 127.0.0.x/8 dev lo  (done automatically below)
//
//  IP map:
//    127.0.0.1   — your real machine (scanner runs here)
//    127.0.0.10  — Firewall / gateway  (minimal services, SSH)
//    127.0.0.11  — Core switch         (SNMP public, Telnet no-auth)
//    127.0.0.20  — DEM server          (FHIR :8080, HL7 :2575, HTTPS :443)
//    127.0.0.21  — PACS / DICOM server (DICOM :104, HTTP admin :8080)
//    127.0.0.30  — Admin PC            (RDP no-NLA, SMB no-signing, HTTP)
//    127.0.0.31  — Doctor workstation  (SSH old version, HTTP)
//    127.0.0.32  — Nurse station       (Telnet open, FTP default creds)
//    127.0.0.33  — Billing PC          (SMB v1!, RDP, MSSQL exposed)
//    127.0.0.40  — Lab analyzer        (Modbus :502, SNMP public, Telnet)
//    127.0.0.41  — Radiology workstation (DICOM :104, old HTTP)
//    127.0.0.50  — Database server     (MySQL :3306 exposed, SSH)
//    127.0.0.51  — Backup server       (FTP default creds, SMB)

var devices = []Device{
	{
		IP:   "127.0.0.10",
		Name: "Firewall / Gateway",
		Role: "firewall",
		Services: []Service{
			{Port: 22, Handler: sshBanner("OpenSSH_8.9p1 Ubuntu-3")},
			{Port: 443, Handler: httpsHandler("Firewall Admin Panel", false)},
		},
	},
	{
		IP:   "127.0.0.11",
		Name: "Core Switch (Cisco)",
		Role: "switch",
		Services: []Service{
			{Port: 23, Handler: telnetNoAuth("Cisco IOS Switch")},   // VULNERABILITY: no auth
			{Port: 161, Handler: snmpPublic("Cisco IOS 15.2, Catalyst 2960"), UDP: true},
			{Port: 22, Handler: sshBanner("OpenSSH_7.4 Cisco")},
		},
	},
	{
		IP:   "127.0.0.20",
		Name: "DEM Server (Dossier Medical Electronique)",
		Role: "dem-server",
		Services: []Service{
			{Port: 8080, Handler: fhirServer()},                     // VULNERABILITY: no auth on FHIR
			{Port: 2575, Handler: hl7Server()},                      // VULNERABILITY: plaintext HL7
			{Port: 443, Handler: httpsHandler("DEM Portal v2.1", true)},
			{Port: 22, Handler: sshBanner("OpenSSH_8.2p1")},
		},
	},
	{
		IP:   "127.0.0.21",
		Name: "PACS / DICOM Server",
		Role: "pacs",
		Services: []Service{
			{Port: 104, Handler: dicomServer()},                     // VULNERABILITY: no TLS
			{Port: 11112, Handler: dicomServer()},
			{Port: 8080, Handler: httpAdminPanel("Orthanc PACS 1.9.0", "admin", "admin")}, // VULNERABILITY: default creds
			{Port: 22, Handler: sshBanner("OpenSSH_7.6p1")},
		},
	},
	{
		IP:   "127.0.0.30",
		Name: "Admin PC (Windows 10)",
		Role: "workstation",
		Services: []Service{
			{Port: 3389, Handler: rdpNoNLA()},                       // VULNERABILITY: no NLA
			{Port: 445, Handler: smbNoSigning("SMBv2")},             // VULNERABILITY: no signing
			{Port: 135, Handler: genericBannerHandler("Microsoft EPMAP")},
			{Port: 80, Handler: httpAdminPanel("Hospital Admin Portal", "admin", "password")},
		},
	},
	{
		IP:   "127.0.0.31",
		Name: "Doctor Workstation (Windows 7)",
		Role: "workstation",
		Services: []Service{
			{Port: 22, Handler: sshBanner("OpenSSH_6.6.1p1")},      // VULNERABILITY: old SSH
			{Port: 80, Handler: httpBanner("Apache/2.2.31 (Win32)")},
			{Port: 445, Handler: smbNoSigning("SMBv1")},             // VULNERABILITY: SMBv1!
		},
	},
	{
		IP:   "127.0.0.32",
		Name: "Nurse Station (Windows 10)",
		Role: "workstation",
		Services: []Service{
			{Port: 23, Handler: telnetWithLogin()},                  // VULNERABILITY: telnet
			{Port: 21, Handler: ftpDefaultCreds("admin", "admin")}, // VULNERABILITY: default FTP
			{Port: 80, Handler: httpBanner("IIS/8.5")},
		},
	},
	{
		IP:   "127.0.0.33",
		Name: "Billing PC (Windows XP)",
		Role: "workstation",
		Services: []Service{
			{Port: 445, Handler: smbV1()},                           // VULNERABILITY: SMBv1 EternalBlue
			{Port: 3389, Handler: rdpNoNLA()},
			{Port: 1433, Handler: mssqlBanner()},                    // VULNERABILITY: DB exposed
			{Port: 135, Handler: genericBannerHandler("Microsoft EPMAP")},
		},
	},
	{
		IP:   "127.0.0.40",
		Name: "Lab Analyzer (Medical IoT)",
		Role: "medical-device",
		Services: []Service{
			{Port: 502, Handler: modbusBanner()},                    // VULNERABILITY: Modbus exposed
			{Port: 23, Handler: telnetNoAuth("Lab Device v3.1")},   // VULNERABILITY: no auth
			{Port: 161, Handler: snmpPublic("Siemens ADVIA 2120i Lab Analyzer"), UDP: true},
		},
	},
	{
		IP:   "127.0.0.41",
		Name: "Radiology Workstation",
		Role: "radiology",
		Services: []Service{
			{Port: 104, Handler: dicomServer()},
			{Port: 80, Handler: httpBanner("Apache/2.4.6")},
			{Port: 22, Handler: sshBanner("OpenSSH_7.4p1")},
		},
	},
	{
		IP:   "127.0.0.50",
		Name: "Database Server (Linux)",
		Role: "database",
		Services: []Service{
			{Port: 3306, Handler: mysqlBanner()},                    // VULNERABILITY: MySQL exposed
			{Port: 22, Handler: sshBanner("OpenSSH_8.0p1")},
			{Port: 161, Handler: snmpPublic("Linux db-server 5.4.0"), UDP: true},
		},
	},
	{
		IP:   "127.0.0.51",
		Name: "Backup Server",
		Role: "backup",
		Services: []Service{
			{Port: 21, Handler: ftpDefaultCreds("admin", "")},      // VULNERABILITY: FTP no password
			{Port: 445, Handler: smbNoSigning("SMBv2")},
			{Port: 22, Handler: sshBanner("OpenSSH_7.9p1")},
		},
	},
}

func main() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║       ALGERIAN HOSPITAL NETWORK SIMULATOR               ║")
	fmt.Println("║       Simulated star-topology — 12 devices              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Add loopback aliases so each device has its own IP
	fmt.Println("[*] Setting up network interfaces...")
	if err := setupLoopbackAliases(); err != nil {
		fmt.Println("[!] Could not add loopback aliases — run with sudo, or use single-IP mode")
		fmt.Println("[!] Falling back to localhost only (127.0.0.1)")
		runSingleHostMode()
		return
	}

	// Start all device simulators
	fmt.Println("[*] Starting simulated devices...")
	fmt.Println()

	started := 0
	for _, device := range devices {
		d := device
		go func() {
			if err := d.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Device %s failed: %v\n", d.IP, err)
			}
		}()
		started++
		time.Sleep(50 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	printTopology()
	printScanCommands()

	// Wait for Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n[*] Shutting down simulator...")
	cleanupLoopbackAliases()
	fmt.Println("[*] Done.")
}

func printTopology() {
	fmt.Println("┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│  HOSPITAL NETWORK TOPOLOGY                              │")
	fmt.Println("├──────────────────┬──────────────┬───────────────────────┤")
	fmt.Printf("│ %-16s │ %-12s │ %-21s │\n", "IP", "Role", "Device")
	fmt.Println("├──────────────────┼──────────────┼───────────────────────┤")
	for _, d := range devices {
		fmt.Printf("│ %-16s │ %-12s │ %-21s │\n", d.IP, d.Role, truncate(d.Name, 21))
	}
	fmt.Println("└──────────────────┴──────────────┴───────────────────────┘")
	fmt.Println()

	fmt.Println("  Known vulnerabilities in this simulation:")
	vulns := []string{
		"  [!] Switch (127.0.0.11)  — Telnet open, no auth + SNMP public",
		"  [!] DEM server (127.0.0.20) — FHIR API unauthenticated, HL7 plaintext",
		"  [!] PACS (127.0.0.21)    — DICOM no TLS, default admin/admin creds",
		"  [!] Admin PC (127.0.0.30) — RDP no NLA, SMB no signing",
		"  [!] Doctor PC (127.0.0.31) — SMBv1 (EternalBlue), old SSH",
		"  [!] Nurse (127.0.0.32)   — Telnet + FTP default creds",
		"  [!] Billing (127.0.0.33) — SMBv1, MSSQL exposed, Windows XP",
		"  [!] Lab device (127.0.0.40) — Modbus open, Telnet no auth",
		"  [!] DB server (127.0.0.50) — MySQL port exposed to network",
		"  [!] Backup (127.0.0.51)  — FTP with no password",
	}
	for _, v := range vulns {
		fmt.Println(v)
	}
	fmt.Println()
}

func printScanCommands() {
	fmt.Println("┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│  RUN YOUR SCANNER NOW — open a new terminal             │")
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	fmt.Println("│                                                         │")
	fmt.Println("│  # Scan a single device:                                │")
	fmt.Println("│  cd ~/go-scanner && go run ./cmd 127.0.0.20             │")
	fmt.Println("│                                                         │")
	fmt.Println("│  # Scan the whole hospital network:                     │")
	fmt.Println("│  go run ./cmd 127.0.0.10/24                             │")
	fmt.Println("│  (or: go run ./cmd 127.0.0.0/24)                        │")
	fmt.Println("│                                                         │")
	fmt.Println("│  Press Ctrl+C here to stop the simulator                │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	fmt.Println()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}