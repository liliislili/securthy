package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const port = "8888"

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health",        corsMiddleware(handleHealth))
	mux.HandleFunc("/api/assess",        corsMiddleware(handleFullAssessment))
	mux.HandleFunc("/api/scan",          corsMiddleware(handleNetworkScan))
	mux.HandleFunc("/api/employee-scan", corsMiddleware(handleEmployeeScan))
	mux.HandleFunc("/api/apply-pack",    corsMiddleware(handleApplyPack))
	mux.HandleFunc("/api/reports",       corsMiddleware(handleListReports))
	mux.HandleFunc("/api/report/",       corsMiddleware(handleGetReport))

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║   Securthy API Server                                   ║")
	fmt.Printf( "║   Listening on http://localhost:%s                    ║\n", port)
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Println("║   POST /api/assess        → FULL assessment (main)      ║")
	fmt.Println("║   POST /api/scan          → network scan only           ║")
	fmt.Println("║   POST /api/employee-scan → employee scan only          ║")
	fmt.Println("║   POST /api/apply-pack    → apply remediation pack      ║")
	fmt.Println("║   GET  /api/reports       → list all reports            ║")
	fmt.Println("║   GET  /api/report/:file  → get specific report         ║")
	fmt.Println("║   GET  /api/health        → health check                ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("  Your backend team calls POST /api/assess to run everything.")
	fmt.Println()

	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// ── Request types ─────────────────────────────────────────────────────────────

type AssessRequest struct {
	Target    string          `json:"target"`    // IP or CIDR
	Employees []EmployeeInput `json:"employees"` // optional
}

type ScanRequest struct {
	Target string `json:"target"`
}

type EmployeeScanRequest struct {
	Employees []EmployeeInput `json:"employees"`
}

type EmployeeInput struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	DeviceIP string `json:"device_ip"`
	Role     string `json:"role"`
}

type PackRequest struct {
	TargetsFile string `json:"targets_file"`
	SSHUser     string `json:"ssh_user"`
	SSHKey      string `json:"ssh_key"`
	SSHPort     int    `json:"ssh_port"`
	WinUser     string `json:"win_user"`
	WinPass     string `json:"win_pass"`
}

// ── Standard response ─────────────────────────────────────────────────────────

type APIResponse struct {
	Success    bool        `json:"success"`
	Message    string      `json:"message"`
	ReportFile string      `json:"report_file,omitempty"`
	Data       interface{} `json:"data,omitempty"`
	Error      string      `json:"error,omitempty"`
	Duration   string      `json:"duration"`
}

// ── MAIN ENDPOINT — full assessment ──────────────────────────────────────────
// This is what the backend calls. Runs network + employee sequentially,
// returns everything in one response.

func handleFullAssessment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, APIResponse{Success: false, Error: "POST required"})
		return
	}

	var req AssessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, APIResponse{Success: false, Error: "Invalid JSON: " + err.Error()})
		return
	}

	if req.Target == "" {
		writeJSON(w, 400, APIResponse{Success: false, Error: "target is required"})
		return
	}

	start := time.Now()
	result := map[string]interface{}{}
	var errors []string

	// ── Step 1: Network scan ─────────────────────────────────────────────────
	log.Printf("[ASSESS] Step 1/3 — network scan on %s", req.Target)
	ctx1, cancel1 := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel1()

	netCmd := exec.CommandContext(ctx1, "./scanner_bin", req.Target)
	netCmd.Stdout = os.Stdout
	netCmd.Stderr = os.Stderr

	if err := netCmd.Run(); err != nil {
		errors = append(errors, "network scan failed: "+err.Error())
	} else {
		networkReport := latestFile("network_report_*.json")
		targetsFile := "targets.json"

		var networkData, targetsData interface{}
		if networkReport != "" {
			d, _ := os.ReadFile(networkReport)
			json.Unmarshal(d, &networkData)
			result["network_report_file"] = networkReport
		}
		if td, err := os.ReadFile(targetsFile); err == nil {
			json.Unmarshal(td, &targetsData)
		}
		result["network"] = networkData
		result["targets"] = targetsData
		log.Printf("[ASSESS] Network scan complete")
	}

	// ── Step 2: Employee scan (if employees provided) ────────────────────────
	if len(req.Employees) > 0 {
		log.Printf("[ASSESS] Step 2/3 — employee scan (%d employees)", len(req.Employees))

		tmpFile := fmt.Sprintf("api_emp_%d.json", time.Now().Unix())
		data, _ := json.MarshalIndent(req.Employees, "", "  ")
		os.WriteFile(tmpFile, data, 0644)
		defer os.Remove(tmpFile)

		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel2()

		empCmd := exec.CommandContext(ctx2, "./employee_bin", tmpFile)
		empCmd.Stdout = os.Stdout
		empCmd.Stderr = os.Stderr

		if err := empCmd.Run(); err != nil {
			errors = append(errors, "employee scan failed: "+err.Error())
		} else {
			empReport := latestFile("employee_report_*.json")
			var empData interface{}
			if empReport != "" {
				d, _ := os.ReadFile(empReport)
				json.Unmarshal(d, &empData)
				result["employee_report_file"] = empReport
			}
			result["employees"] = empData
			log.Printf("[ASSESS] Employee scan complete")

			// ── Step 3: Generate remediation plan ───────────────────────────
			log.Printf("[ASSESS] Step 3/3 — generating remediation plan")
			if empReport != "" {
				ctx3, cancel3 := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel3()

				planCmd := exec.CommandContext(ctx3, "./employee_packs_bin", empReport)
				planCmd.Stdout = os.Stdout
				planCmd.Stderr = os.Stderr
				planCmd.Run() // don't fail if this fails

				planReport := latestFile("employee_remediation_*.json")
				if planReport != "" {
					var planData interface{}
					d, _ := os.ReadFile(planReport)
					json.Unmarshal(d, &planData)
					result["remediation_plan"] = planData
					result["remediation_plan_file"] = planReport
				}
			}
		}
	} else {
		log.Printf("[ASSESS] Step 2/3 — no employees provided, skipping")
		result["employees"] = nil
	}

	// ── Build summary ─────────────────────────────────────────────────────────
	var isoScore interface{}
	var packTier interface{}
	if t, ok := result["targets"]; ok && t != nil {
		if tMap, ok := t.(map[string]interface{}); ok {
			isoScore = tMap["iso_score"]
			packTier = tMap["recommended_tier"]
		}
	}

	result["summary"] = map[string]interface{}{
		"iso_score":        isoScore,
		"recommended_pack": packTier,
		"duration":         time.Since(start).Round(time.Second).String(),
		"errors":           errors,
	}

	duration := time.Since(start).Round(time.Second)
	log.Printf("[ASSESS] Full assessment complete in %s", duration)

	writeJSON(w, 200, APIResponse{
		Success:  len(errors) == 0,
		Message:  fmt.Sprintf("Assessment complete — %s", req.Target),
		Duration: duration.String(),
		Data:     result,
	})
}

// ── Individual handlers (still available) ─────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, APIResponse{
		Success: true,
		Message: "Securthy API is running",
		Data: map[string]string{
			"version":   "1.0.0",
			"timestamp": time.Now().Format(time.RFC3339),
		},
	})
}

func handleNetworkScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, APIResponse{Success: false, Error: "POST required"})
		return
	}
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, APIResponse{Success: false, Error: "Invalid JSON"})
		return
	}
	if req.Target == "" {
		writeJSON(w, 400, APIResponse{Success: false, Error: "target required"})
		return
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "./scanner_bin", req.Target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		writeJSON(w, 500, APIResponse{Success: false, Error: err.Error(), Duration: time.Since(start).Round(time.Second).String()})
		return
	}

	reportFile := latestFile("network_report_*.json")
	var reportData, targetsData interface{}
	if reportFile != "" {
		d, _ := os.ReadFile(reportFile)
		json.Unmarshal(d, &reportData)
	}
	if td, err := os.ReadFile("targets.json"); err == nil {
		json.Unmarshal(td, &targetsData)
	}

	writeJSON(w, 200, APIResponse{
		Success: true, Message: "Network scan complete",
		ReportFile: reportFile,
		Duration:   time.Since(start).Round(time.Second).String(),
		Data:       map[string]interface{}{"report": reportData, "targets": targetsData},
	})
}

func handleEmployeeScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, APIResponse{Success: false, Error: "POST required"})
		return
	}
	var req EmployeeScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, APIResponse{Success: false, Error: "Invalid JSON"})
		return
	}
	if len(req.Employees) == 0 {
		writeJSON(w, 400, APIResponse{Success: false, Error: "employees array required"})
		return
	}

	tmpFile := fmt.Sprintf("api_emp_%d.json", time.Now().Unix())
	data, _ := json.MarshalIndent(req.Employees, "", "  ")
	os.WriteFile(tmpFile, data, 0644)
	defer os.Remove(tmpFile)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "./employee_bin", tmpFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		writeJSON(w, 500, APIResponse{Success: false, Error: err.Error(), Duration: time.Since(start).Round(time.Second).String()})
		return
	}

	reportFile := latestFile("employee_report_*.json")
	var reportData interface{}
	if reportFile != "" {
		d, _ := os.ReadFile(reportFile)
		json.Unmarshal(d, &reportData)
	}

	writeJSON(w, 200, APIResponse{
		Success: true, Message: "Employee scan complete",
		ReportFile: reportFile,
		Duration:   time.Since(start).Round(time.Second).String(),
		Data:       reportData,
	})
}

func handleApplyPack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, APIResponse{Success: false, Error: "POST required"})
		return
	}
	var req PackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, APIResponse{Success: false, Error: "Invalid JSON"})
		return
	}
	if req.TargetsFile == "" {
		req.TargetsFile = "targets.json"
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
	}
	if req.SSHPort == 0 {
		req.SSHPort = 22
	}

	args := []string{
		"--targets=" + req.TargetsFile,
		fmt.Sprintf("--ssh-user=%s", req.SSHUser),
		fmt.Sprintf("--ssh-port=%d", req.SSHPort),
	}
	if req.SSHKey != "" {
		args = append(args, "--ssh-key="+req.SSHKey)
	}
	if req.WinUser != "" {
		args = append(args, "--win-user="+req.WinUser)
	}
	if req.WinPass != "" {
		args = append(args, "--win-pass="+req.WinPass)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "./packs_bin", args...)
	cmd.Stdin = strings.NewReader("y\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		writeJSON(w, 500, APIResponse{Success: false, Error: err.Error(), Duration: time.Since(start).Round(time.Second).String()})
		return
	}

	reportFile := latestFile("pack_report_*.json")
	var reportData interface{}
	if reportFile != "" {
		d, _ := os.ReadFile(reportFile)
		json.Unmarshal(d, &reportData)
	}

	writeJSON(w, 200, APIResponse{
		Success: true, Message: "Pack applied",
		ReportFile: reportFile,
		Duration:   time.Since(start).Round(time.Second).String(),
		Data:       reportData,
	})
}

func handleListReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, APIResponse{Success: false, Error: "GET required"})
		return
	}
	type ReportInfo struct {
		Filename string `json:"filename"`
		Type     string `json:"type"`
		Size     int64  `json:"size_bytes"`
		Created  string `json:"created"`
	}
	var reports []ReportInfo
	for _, pattern := range []string{
		"network_report_*.json", "employee_report_*.json",
		"pack_report_*.json", "employee_remediation_*.json",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				continue
			}
			reports = append(reports, ReportInfo{
				Filename: match,
				Type:     strings.Split(match, "_")[0],
				Size:     info.Size(),
				Created:  info.ModTime().Format(time.RFC3339),
			})
		}
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Created > reports[j].Created })
	writeJSON(w, 200, APIResponse{Success: true, Message: fmt.Sprintf("%d reports", len(reports)), Data: reports})
}

func handleGetReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, APIResponse{Success: false, Error: "GET required"})
		return
	}
	filename := strings.TrimPrefix(r.URL.Path, "/api/report/")
	if filename == "" || strings.Contains(filename, "/") || strings.Contains(filename, "..") || !strings.HasSuffix(filename, ".json") {
		writeJSON(w, 400, APIResponse{Success: false, Error: "invalid filename"})
		return
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		writeJSON(w, 404, APIResponse{Success: false, Error: "not found: " + filename})
		return
	}
	var reportData interface{}
	json.Unmarshal(data, &reportData)
	writeJSON(w, 200, APIResponse{Success: true, ReportFile: filename, Data: reportData})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		next(w, r)
	}
}

func latestFile(pattern string) string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	return matches[len(matches)-1]
}
