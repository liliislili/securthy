package models

type EmployeeTarget struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	DeviceIP string `json:"device_ip"`
	Role     string `json:"role"`
}

type HumanScanResult struct {
	EmployeeID string   `json:"employee_id"`
	Name       string   `json:"name"`
	Role       string   `json:"role"`
	Phishing   float64  `json:"phishing"`
	Password   float64  `json:"password"`
	WiFi       float64  `json:"wifi"`
	Email      float64  `json:"email"`
	Session    float64  `json:"session"`
	Privilege  float64  `json:"privilege"`
	USB        float64  `json:"usb"`
	Browser    float64  `json:"browser"`
	Data       float64  `json:"data"`
	TotalRisk  float64  `json:"total_risk"`
	Grade      string   `json:"grade"`
	Findings   []string `json:"findings,omitempty"`
}

func GradeFromRisk(risk float64) string {
	switch {
	case risk < 20:
		return "A — low risk"
	case risk < 40:
		return "B — moderate"
	case risk < 60:
		return "C — significant risk"
	case risk < 80:
		return "D — high risk"
	default:
		return "F — critical"
	}
}
