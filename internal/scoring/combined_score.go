package scoring

import "fmt"

type CombinedISOReport struct {
	NetworkScore  int     `json:"network_score"`
	NetworkGrade  string  `json:"network_grade"`
	EmployeeRisk  float64 `json:"employee_risk"`
	EmployeeScore int     `json:"employee_score"`
	EmployeeGrade string  `json:"employee_grade"`
	CombinedScore int     `json:"combined_score"`
	CombinedGrade string  `json:"combined_grade"`
	OverallRisk   string  `json:"overall_risk"`
	PackTier      string  `json:"recommended_pack"`
	Recommendation string `json:"recommendation"`
}

func CalculateCombined(networkScore int, employeeAvgRisk float64) CombinedISOReport {
	r := CombinedISOReport{
		NetworkScore:  networkScore,
		NetworkGrade:  gradeFromScore(networkScore),
		EmployeeRisk:  employeeAvgRisk,
		EmployeeScore: int(100 - employeeAvgRisk),
		EmployeeGrade: gradeFromScore(int(100 - employeeAvgRisk)),
	}
	combined := float64(networkScore)*0.60 + float64(r.EmployeeScore)*0.40
	r.CombinedScore = int(combined)
	r.CombinedGrade = gradeFromScore(r.CombinedScore)
	switch {
	case r.CombinedScore >= 80:
		r.OverallRisk = "LOW — good security posture"
	case r.CombinedScore >= 60:
		r.OverallRisk = "MODERATE — significant gaps"
	case r.CombinedScore >= 40:
		r.OverallRisk = "HIGH — immediate action required"
	default:
		r.OverallRisk = "CRITICAL — urgent remediation needed"
	}
	if r.CombinedScore < 35 {
		r.PackTier = "conformite"
	} else if r.CombinedScore < 60 {
		r.PackTier = "securite"
	} else {
		r.PackTier = "essentiel"
	}
	if networkScore < 50 {
		r.Recommendation = fmt.Sprintf("Network critically exposed (%d/100) — run Pack %s immediately", networkScore, r.PackTier)
	} else if employeeAvgRisk > 60 {
		r.Recommendation = fmt.Sprintf("Employee risk high (%.0f/100) — mandatory training required within 30 days", employeeAvgRisk)
	} else {
		r.Recommendation = fmt.Sprintf("Score %d/100 — implement Pack %s and run employee training", r.CombinedScore, r.PackTier)
	}
	return r
}

func PrettyPrintCombined(r CombinedISOReport) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║      COMBINED SECURITY POSTURE — Securthy DZ        ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Network ISO score  : %3d/100 — %-26s ║\n", r.NetworkScore, r.NetworkGrade)
	fmt.Printf("║  Employee ISO score : %3d/100 — %-26s ║\n", r.EmployeeScore, r.EmployeeGrade)
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  COMBINED SCORE     : %3d/100 — %-26s ║\n", r.CombinedScore, r.CombinedGrade)
	fmt.Printf("║  Overall risk       : %-38s ║\n", r.OverallRisk)
	fmt.Printf("║  Recommended pack   : %-38s ║\n", r.PackTier)
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("  Recommendation: " + r.Recommendation)
}
