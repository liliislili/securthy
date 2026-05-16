package goscanner
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

// ── API server for Securthy scanner ──────────────────────────────────────────
//
// Exposes your scanner as HTTP endpoints so the backend team
// can call it from any language (Node.js, Python, etc.)
//
// Endpoints:
//   POST /api/scan              → run network scan
//   POST /api/employee-scan     → run employee scan
//   POST /api/apply-pack        → run remediation pack
//   GET  /api/reports           → list all generated reports
//   GET  /api/report/:filename  → get a specific report
//   GET  /api/health            → health check
//
// Run: go run ./api
// Default port: 8888

const port = "8888"

func main() {
	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("/api/health", corsMiddleware(handleHealth))
	mux.HandleFunc("/api/scan", corsMiddleware(handleNetworkScan))
	mux.HandleFunc("/api/employee-scan", corsMiddleware(handleEmployeeScan))
	mux.HandleFunc("/api/apply-pack", corsMiddleware(handleApplyPack))
	mux.HandleFunc("/api/reports", corsMiddleware(handleListReports))
	mux.HandleFunc("/api/report/", corsMiddleware(handleGetReport))

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║   Securthy API Server                                   ║")
	fmt.Printf("║   Listening on http://localhost:%s                    ║\n", port)
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Println("║   POST /api/scan              → network scan            ║")
	fmt.Println("║   POST /api/employee-scan     → employee scan           ║")
	fmt.Println("║   POST /api/apply-pack        → apply remediation pack  ║")
	fmt.Println("║   GET  /api/reports           → list all reports        ║")
	fmt.Println("║   GET  /api/report/:file      → get specific report     ║")
	fmt.Println("║   GET  /api/health            → health check            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// ── Request / Response types ──────────────────────────────────────────────────

type ScanRequest struct {
	Target string `json:"target"` // IP or CIDR e.g. "192.168.1.0/24"
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
	TargetsFile string `json:"targets_file"` // path to targets.json
	SSHUser     string `json:"ssh_user"`
	SSHKey      string `json:"ssh_key"`
	SSHPort     int    `json:"ssh_port"`
	WinUser     string `json:"win_user"`
	WinPass     string `json:"win_pass"`
}

type APIResponse struct {
	Success    bool        `json:"success"`
	Message    string      `json:"message"`
	ReportFile string      `json:"report_file,omitempty"`
	Data       interface{} `json:"data,omitempty"`
	Error      string      `json:"error,omitempty"`
	Duration   string      `json:"duration"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

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
		writeJSON(w, 400, APIResponse{Success: false, Error: "Invalid JSON: " + err.Error()})
		return
	}

	if req.Target == "" {
		writeJSON(w, 400, APIResponse{Success: false, Error: "target is required (e.g. '192.168.1.0/24')"})
		return
	}

	log.Printf("[SCAN] Starting network scan on %s", req.Target)
	start := time.Now()

	// Run scanner binary with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "./scanner_bin", req.Target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		writeJSON(w, 500, APIResponse{
			Success:  false,
			Error:    "Scan failed: " + err.Error(),
			Duration: time.Since(start).Round(time.Second).String(),
		})
		return
	}

	// Find the latest network report
	reportFile := latestFile("network_report_*.json")
	targetsFile := "targets.json"

	duration := time.Since(start).Round(time.Second)
	log.Printf("[SCAN] Completed in %s → %s", duration, reportFile)

	// Read and return the report data
	var reportData interface{}
	if reportFile != "" {
		data, _ := os.ReadFile(reportFile)
		json.Unmarshal(data, &reportData)
	}

	// Read targets.json for pack info
	var targetsData interface{}
	if tData, err := os.ReadFile(targetsFile); err == nil {
		json.Unmarshal(tData, &targetsData)
	}

	writeJSON(w, 200, APIResponse{
		Success:    true,
		Message:    fmt.Sprintf("Network scan complete — %s", req.Target),
		ReportFile: reportFile,
		Duration:   duration.String(),
		Data: map[string]interface{}{
			"report":  reportData,
			"targets": targetsData,
		},
	})
}

func handleEmployeeScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, APIResponse{Success: false, Error: "POST required"})
		return
	}

	var req EmployeeScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, APIResponse{Success: false, Error: "Invalid JSON: " + err.Error()})
		return
	}

	if len(req.Employees) == 0 {
		writeJSON(w, 400, APIResponse{Success: false, Error: "employees array is required"})
		return
	}

	// Write employees to temp file
	tmpFile := fmt.Sprintf("api_employees_%d.json", time.Now().Unix())
	data, _ := json.MarshalIndent(req.Employees, "", "  ")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		writeJSON(w, 500, APIResponse{Success: false, Error: "Failed to write employees file"})
		return
	}
	defer os.Remove(tmpFile)

	log.Printf("[EMPLOYEE] Scanning %d employees", len(req.Employees))
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "./employee_bin", tmpFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		writeJSON(w, 500, APIResponse{
			Success:  false,
			Error:    "Employee scan failed: " + err.Error(),
			Duration: time.Since(start).Round(time.Second).String(),
		})
		return
	}

	reportFile := latestFile("employee_report_*.json")
	duration := time.Since(start).Round(time.Second)
	log.Printf("[EMPLOYEE] Completed in %s → %s", duration, reportFile)

	var reportData interface{}
	if reportFile != "" {
		rData, _ := os.ReadFile(reportFile)
		json.Unmarshal(rData, &reportData)
	}

	writeJSON(w, 200, APIResponse{
		Success:    true,
		Message:    fmt.Sprintf("Employee scan complete — %d employees", len(req.Employees)),
		ReportFile: reportFile,
		Duration:   duration.String(),
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
		writeJSON(w, 400, APIResponse{Success: false, Error: "Invalid JSON: " + err.Error()})
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

	// Build packs_bin args
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

	log.Printf("[PACK] Applying remediation pack")
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Pipe "y" to auto-confirm the pack
	cmd := exec.CommandContext(ctx, "./packs_bin", args...)
	cmd.Stdin = strings.NewReader("y\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		writeJSON(w, 500, APIResponse{
			Success:  false,
			Error:    "Pack failed: " + err.Error(),
			Duration: time.Since(start).Round(time.Second).String(),
		})
		return
	}

	reportFile := latestFile("pack_report_*.json")
	duration := time.Since(start).Round(time.Second)
	log.Printf("[PACK] Completed in %s", duration)

	var reportData interface{}
	if reportFile != "" {
		rData, _ := os.ReadFile(reportFile)
		json.Unmarshal(rData, &reportData)
	}

	writeJSON(w, 200, APIResponse{
		Success:    true,
		Message:    "Remediation pack applied successfully",
		ReportFile: reportFile,
		Duration:   duration.String(),
		Data:       reportData,
	})
}

func handleListReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, APIResponse{Success: false, Error: "GET required"})
		return
	}

	patterns := []string{
		"network_report_*.json",
		"employee_report_*.json",
		"pack_report_*.json",
		"employee_remediation_*.json",
		"combined_report_*.json",
	}

	type ReportInfo struct {
		Filename string `json:"filename"`
		Type     string `json:"type"`
		Size     int64  `json:"size_bytes"`
		Created  string `json:"created"`
	}

	var reports []ReportInfo

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				continue
			}
			reportType := strings.Split(match, "_")[0]
			reports = append(reports, ReportInfo{
				Filename: match,
				Type:     reportType,
				Size:     info.Size(),
				Created:  info.ModTime().Format(time.RFC3339),
			})
		}
	}

	// Sort by newest first
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].Created > reports[j].Created
	})

	writeJSON(w, 200, APIResponse{
		Success: true,
		Message: fmt.Sprintf("%d reports found", len(reports)),
		Data:    reports,
	})
}

func handleGetReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, APIResponse{Success: false, Error: "GET required"})
		return
	}

	// Extract filename from URL: /api/report/network_report_123.json
	filename := strings.TrimPrefix(r.URL.Path, "/api/report/")
	if filename == "" {
		writeJSON(w, 400, APIResponse{Success: false, Error: "filename required"})
		return
	}

	// Security: only allow json files, no path traversal
	if strings.Contains(filename, "/") || strings.Contains(filename, "..") || !strings.HasSuffix(filename, ".json") {
		writeJSON(w, 400, APIResponse{Success: false, Error: "invalid filename"})
		return
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		writeJSON(w, 404, APIResponse{Success: false, Error: "report not found: " + filename})
		return
	}

	var reportData interface{}
	json.Unmarshal(data, &reportData)

	writeJSON(w, 200, APIResponse{
		Success:    true,
		ReportFile: filename,
		Data:       reportData,
	})
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
	// Sort and return newest
	sort.Strings(matches)
	return matches[len(matches)-1]
}