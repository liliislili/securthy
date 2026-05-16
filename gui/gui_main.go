package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Simple terminal GUI for Securthy scanner
// No external dependencies — pure Go

const (
	colorReset  = "\033[0m"
	colorTeal   = "\033[36m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	clearScreen = "\033[2J\033[H"
)

func main() {
	showBanner()
	showMenu()
}

func showBanner() {
	fmt.Print(clearScreen)
	fmt.Println(colorTeal + colorBold)
	fmt.Println("  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ████████╗██╗  ██╗██╗   ██╗")
	fmt.Println("  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗╚══██╔══╝██║  ██║╚██╗ ██╔╝")
	fmt.Println("  ███████╗█████╗  ██║     ██║   ██║██████╔╝   ██║   ███████║ ╚████╔╝ ")
	fmt.Println("  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗   ██║   ██╔══██║  ╚██╔╝  ")
	fmt.Println("  ███████║███████╗╚██████╗╚██████╔╝██║  ██║   ██║   ██║  ██║   ██║   ")
	fmt.Println("  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝  ")
	fmt.Println(colorReset)
	fmt.Println(colorDim + "  Healthcare Network Security Platform — Algeria" + colorReset)
	fmt.Println(colorDim + "  ISO 27001:2022 Compliance Assessment" + colorReset)
	fmt.Println()
	fmt.Println(strings.Repeat("─", 70))
	fmt.Println()
}

func showMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println(colorBold + "  MAIN MENU" + colorReset)
		fmt.Println()
		fmt.Println("  " + colorTeal + "[1]" + colorReset + "  Network Scan          — Scan hospital network for vulnerabilities")
		fmt.Println("  " + colorTeal + "[2]" + colorReset + "  Employee Scan         — Assess staff security awareness")
		fmt.Println("  " + colorTeal + "[3]" + colorReset + "  Full Assessment       — Network + Employee (recommended)")
		fmt.Println("  " + colorTeal + "[4]" + colorReset + "  Apply Remediation     — Push fixes to scanned machines")
		fmt.Println("  " + colorTeal + "[5]" + colorReset + "  Start Simulator       — Launch demo hospital network")
		fmt.Println("  " + colorTeal + "[6]" + colorReset + "  View Last Report      — Show latest scan results")
		fmt.Println("  " + colorTeal + "[7]" + colorReset + "  Start API Server      — Expose scanner via HTTP")
		fmt.Println("  " + colorRed + "[0]" + colorReset + "  Exit")
		fmt.Println()
		fmt.Print("  " + colorBold + "Choose [0-7]: " + colorReset)

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		fmt.Println()

		switch input {
		case "1":
			runNetworkScan(reader)
		case "2":
			runEmployeeScan(reader)
		case "3":
			runFullAssessment(reader)
		case "4":
			runRemediation(reader)
		case "5":
			runSimulator()
		case "6":
			viewLastReport()
		case "7":
			runAPIServer()
		case "0":
			fmt.Println(colorTeal + "  Goodbye." + colorReset)
			fmt.Println()
			os.Exit(0)
		default:
			fmt.Println(colorRed + "  Invalid choice." + colorReset)
			fmt.Println()
		}
	}
}

func runNetworkScan(reader *bufio.Reader) {
	fmt.Print("  Target network (e.g. 192.168.1.0/24): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		target = "127.0.0.0/24"
	}

	printStep("Starting network scan on " + target)
	runCommand("./scanner_bin", target)
	showReportPaths()
}

func runEmployeeScan(reader *bufio.Reader) {
	fmt.Print("  Employees file (default: employees.json): ")
	file, _ := reader.ReadString('\n')
	file = strings.TrimSpace(file)
	if file == "" {
		file = "employees.json"
	}

	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Println(colorRed + "  [!] File not found: " + file + colorReset)
		fmt.Println()
		return
	}

	printStep("Starting employee scan from " + file)
	runCommand("./employee_bin", file)
	showReportPaths()
}

func runFullAssessment(reader *bufio.Reader) {
	fmt.Print("  Target network (e.g. 192.168.1.0/24): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		target = "127.0.0.0/24"
	}

	empFile := "employees.json"
	if _, err := os.Stat(empFile); !os.IsNotExist(err) {
		printStep("Running full assessment (network + employees)")
		runCommand("./scanner_bin", target, "--employees="+empFile)
	} else {
		printStep("Running network scan (no employees.json found)")
		runCommand("./scanner_bin", target)
	}

	showReportPaths()
}

func runRemediation(reader *bufio.Reader) {
	fmt.Println("  Pack tiers:")
	fmt.Println("  " + colorTeal + "[1]" + colorReset + " Essentiel  — Quick wins (3-5 days)")
	fmt.Println("  " + colorTeal + "[2]" + colorReset + " Securite   — Full architecture (3-4 weeks)")
	fmt.Println("  " + colorTeal + "[3]" + colorReset + " Conformite — Full ISO compliance (2-3 months)")
	fmt.Println("  " + colorTeal + "[d]" + colorReset + " Demo mode  — Simulate fixes (no real SSH needed)")
	fmt.Println()
	fmt.Print("  Choose [1/2/3/d]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "d" {
		printStep("Running pack in DEMO mode (simulated)")
		runCommand("./packs_bin", "--targets=targets.json", "--demo")
		return
	}

	tiers := map[string]string{"1": "essentiel", "2": "securite", "3": "conformite"}
	tier, ok := tiers[choice]
	if !ok {
		fmt.Println(colorRed + "  Invalid choice." + colorReset)
		fmt.Println()
		return
	}

	fmt.Print("  SSH user (default: root): ")
	sshUser, _ := reader.ReadString('\n')
	sshUser = strings.TrimSpace(sshUser)
	if sshUser == "" {
		sshUser = "root"
	}

	fmt.Print("  SSH key path (default: ~/.ssh/id_rsa): ")
	sshKey, _ := reader.ReadString('\n')
	sshKey = strings.TrimSpace(sshKey)
	if sshKey == "" {
		sshKey = "~/.ssh/id_rsa"
	}

	fmt.Print("  SSH port (default: 22): ")
	sshPort, _ := reader.ReadString('\n')
	sshPort = strings.TrimSpace(sshPort)
	if sshPort == "" {
		sshPort = "22"
	}

	printStep("Applying Pack " + strings.ToUpper(tier))
	runCommand("./packs_bin",
		"--targets=targets.json",
		"--tier="+tier,
		"--ssh-user="+sshUser,
		"--ssh-key="+sshKey,
		"--ssh-port="+sshPort,
	)
}

func runSimulator() {
	printStep("Starting hospital simulator (Ctrl+C to stop)")
	fmt.Println(colorYellow + "  Starting 12-device hospital network simulation..." + colorReset)
	fmt.Println(colorDim + "  Run this in a separate terminal:" + colorReset)
	fmt.Println(colorTeal + "  sudo /usr/local/go/bin/go run ./simulator" + colorReset)
	fmt.Println()

	fmt.Print("  Launch simulator now? [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(confirm)) == "y" {
		cmd := exec.Command("sudo", "/usr/local/go/bin/go", "run", "./simulator")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}

func viewLastReport() {
	// Find latest .txt report
	entries, err := os.ReadDir(".")
	if err != nil {
		fmt.Println(colorRed + "  Cannot read directory" + colorReset)
		return
	}

	latest := ""
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".txt") && strings.HasPrefix(e.Name(), "report_") {
			if e.Name() > latest {
				latest = e.Name()
			}
		}
	}

	if latest == "" {
		fmt.Println(colorYellow + "  No reports found. Run a scan first." + colorReset)
		fmt.Println()
		return
	}

	content, err := os.ReadFile(latest)
	if err != nil {
		fmt.Println(colorRed + "  Cannot read report: " + err.Error() + colorReset)
		return
	}

	fmt.Println(colorTeal + "  Report: " + latest + colorReset)
	fmt.Println(strings.Repeat("─", 70))
	fmt.Println(string(content))
	fmt.Println(strings.Repeat("─", 70))
	fmt.Println()

	secFile := strings.TrimSuffix(latest, ".txt") + ".sec"
	if _, err := os.Stat(secFile); err == nil {
		fmt.Println(colorGreen + "  [+] Encrypted version: " + secFile + colorReset)
		fmt.Println(colorDim + "      (readable only by Securthy platform)" + colorReset)
		fmt.Println()
	}
}

func runAPIServer() {
	printStep("Starting API server on port 8888")
	runCommand("./api_bin")
}

func runCommand(name string, args ...string) {
	fmt.Println()
	fmt.Println(strings.Repeat("─", 70))

	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		fmt.Println(colorRed + "\n  [!] Error: " + err.Error() + colorReset)
	}

	fmt.Println(strings.Repeat("─", 70))
	fmt.Println()
	fmt.Println("  Press Enter to return to menu...")
	bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Print(clearScreen)
	showBanner()
}

func printStep(msg string) {
	fmt.Println(colorTeal + "  [*] " + msg + colorReset)
	fmt.Println(colorDim + "      " + time.Now().Format("15:04:05") + colorReset)
	fmt.Println()
}

func showReportPaths() {
	entries, _ := os.ReadDir(".")
	latestTxt, latestSec, latestJson := "", "", ""
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "report_") {
			if strings.HasSuffix(n, ".txt") && n > latestTxt {
				latestTxt = n
			}
			if strings.HasSuffix(n, ".sec") && n > latestSec {
				latestSec = n
			}
			if strings.HasSuffix(n, ".json") && n > latestJson {
				latestJson = n
			}
		}
	}
	fmt.Println()
	if latestTxt != "" {
		fmt.Println(colorGreen + "  [+] TXT report (readable):  " + latestTxt + colorReset)
	}
	if latestSec != "" {
		fmt.Println(colorGreen + "  [+] SEC report (encrypted): " + latestSec + colorReset)
		fmt.Println(colorDim + "      Readable only by Securthy platform" + colorReset)
	}
	if latestJson != "" {
		fmt.Println(colorGreen + "  [+] JSON report (full data): " + latestJson + colorReset)
	}
}
