package logs

import (
	"os"
	"strings"
)

type AuthFinding struct {
	BruteForceDetected bool
	FailedLogins       int
	SuspiciousIPs      []string
}

// Parses /var/log/auth.log (Linux security log)

func AnalyzeAuthLog() AuthFinding {

	data, err := os.ReadFile("/var/log/auth.log")
	if err != nil {
		return AuthFinding{}
	}

	content := string(data)

	lines := strings.Split(content, "\n")

	failed := 0
	ipMap := map[string]bool{}

	for _, line := range lines {

		if strings.Contains(line, "Failed password") {
			failed++
		}

		// extract simple IP pattern (light heuristic)
		if strings.Contains(line, "from ") {
			parts := strings.Split(line, "from ")
			if len(parts) > 1 {
				ip := strings.Fields(parts[1])[0]
				ipMap[ip] = true
			}
		}
	}

	suspicious := []string{}
	for ip := range ipMap {
		suspicious = append(suspicious, ip)
	}

	return AuthFinding{
		BruteForceDetected: failed > 20,
		FailedLogins:       failed,
		SuspiciousIPs:      suspicious,
	}
}
