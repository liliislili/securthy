package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"go-scanner/internal/human"
	"go-scanner/internal/human/iso"
	"go-scanner/internal/human/phishing"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	targets, err := loadEmployees(os.Args[1])
	if err != nil {
		fmt.Println("[!] Error loading employees:", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║   Securthy DZ — Employee Security Assessment         ║")
	fmt.Printf("║   Scanning %-3d employees                                ║\n", len(targets))
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	var results []human.HumanScanResult

	for _, target := range targets {
		fmt.Printf("[*] %s (%s) — %s\n", target.Name, target.Role, target.Email)
		result := human.RunHumanScan(target)
		results = append(results, result)
		printEmployeeResult(result)
	}

	avgRisk := averageRisk(results)
	isoReport := buildHumanISO(results)

	fmt.Println("\n" + strings.Repeat("═", 60))
	fmt.Printf("  EMPLOYEE SECURITY SCORE: %.0f/100 risk — %s\n",
		avgRisk, human.GradeFromRisk(avgRisk))
	fmt.Println(strings.Repeat("═", 60))
	printISOReport(isoReport)

	if len(targets) > 0 && strings.Contains(targets[0].Email, "@") {
		domain := strings.Split(targets[0].Email, "@")[1]
		fmt.Printf("\n[*] Email security check for domain: %s\n", domain)
		phishRisk := phishing.AssessPhishingRisk(domain, "")
		fmt.Println(phishing.GeneratePhishingReport(domain, phishRisk))
	}

	saveResults(results, avgRisk)
}

func loadEmployees(path string) ([]human.EmployeeTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []human.EmployeeTarget
	return targets, json.Unmarshal(data, &targets)
}

func printEmployeeResult(r human.HumanScanResult) {
	fmt.Printf("  %-25s Grade: %-20s Risk: %.0f/100\n", r.Name, r.Grade, r.TotalRisk)
	fmt.Printf("  Phishing:%.0f  Password:%.0f  WiFi:%.0f  Email:%.0f\n",
		r.Phishing, r.Password, r.WiFi, r.Email)
	fmt.Printf("  Session:%.0f  Privilege:%.0f  USB:%.0f  Browser:%.0f\n\n",
		r.Session, r.Privilege, r.USB, r.Browser)
}

func averageRisk(results []human.HumanScanResult) float64 {
	if len(results) == 0 {
		return 0
	}
	total := 0.0
	for _, r := range results {
		total += r.TotalRisk
	}
	return total / float64(len(results))
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

func printISOReport(r iso.ISOReport) {
	fmt.Println("\n  ISO 27001 Human Controls:")
	for _, c := range r.Controls {
		status := "✓"
		if !c.Passed {
			status = "✗"
		}
		fmt.Printf("  [%s] %-10s source:%-12s risk:%.0f\n",
			status, c.ControlID, c.Source, c.RiskScore)
	}
	fmt.Printf("\n  Average control risk: %.0f/100\n", r.Total)
}

func saveResults(results []human.HumanScanResult, avgRisk float64) {
	type Report struct {
		Timestamp string                  `json:"timestamp"`
		AvgRisk   float64                 `json:"average_risk"`
		Grade     string                  `json:"grade"`
		Employees []human.HumanScanResult `json:"employees"`
	}
	report := Report{
		Timestamp: time.Now().Format(time.RFC3339),
		AvgRisk:   avgRisk,
		Grade:     human.GradeFromRisk(avgRisk),
		Employees: results,
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	filename := fmt.Sprintf("employee_report_%d.json", time.Now().Unix())
	os.WriteFile(filename, data, 0644)
	fmt.Printf("\n[+] Employee report saved: %s\n", filename)
}

func printUsage() {
	fmt.Println(`
Securthy DZ — Employee Security Assessment

Usage:
  go run ./employee employees.json

Employee file format:
  [{"id":"E001","name":"Dr. Benali","email":"benali@chu.dz","device_ip":"192.168.1.31","role":"doctor"}]

Roles: doctor | nurse | admin | billing | it
`)
}
