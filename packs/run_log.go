package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type FixResult struct {
	Host    string
	Fix     string
	OS      string
	Success bool
	Output  string
	Error   string
	Time    string
}

type RunLog struct {
	Results   []FixResult
	StartTime time.Time
}

func NewRunLog() *RunLog {
	return &RunLog{StartTime: time.Now()}
}

func (l *RunLog) Add(host, fix, os string, success bool, output, errMsg string) {
	icon := "✓"
	if !success {
		icon = "✗"
	}
	fmt.Printf("  [%s] %-16s %-35s", icon, host, fix)
	if success {
		fmt.Println()
	} else {
		fmt.Printf(" ERROR: %s\n", errMsg)
	}

	l.Results = append(l.Results, FixResult{
		Host:    host,
		Fix:     fix,
		OS:      os,
		Success: success,
		Output:  output,
		Error:   errMsg,
		Time:    time.Now().Format(time.RFC3339),
	})
}

func (l *RunLog) PrintSummary() {
	passed, failed := 0, 0
	for _, r := range l.Results {
		if r.Success {
			passed++
		} else {
			failed++
		}
	}

	elapsed := time.Since(l.StartTime).Round(time.Second)
	fmt.Println("\n" + strings.Repeat("═", 58))
	fmt.Printf("  Completed in %s\n", elapsed)
	fmt.Printf("  Fixes applied : %d succeeded, %d failed\n", passed, failed)

	if failed > 0 {
		fmt.Println("\n  Failed fixes:")
		for _, r := range l.Results {
			if !r.Success {
				fmt.Printf("    - [%s] %s: %s\n", r.Host, r.Fix, r.Error)
			}
		}
	}
	fmt.Println(strings.Repeat("═", 58))
}

func (l *RunLog) SaveReport(path string) {
	data, _ := json.MarshalIndent(l.Results, "", "  ")
	os.WriteFile(path, data, 0644)
	fmt.Printf("\n  Full log saved: %s\n", path)
}
