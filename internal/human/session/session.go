package session

import (
	"fmt"
	"os"
	"os/user"
	"strings"

	"go-scanner/internal/human/models"
)

func Run(target models.EmployeeTarget) float64 {
	risk := 0.0

	u, err := user.Current()
	if err == nil {
		if strings.Contains(strings.ToLower(u.Username), "admin") {
			risk += 20
		}
	}

	uptime := getUptime()
	if uptime < 3600 {
		risk += 10
	}

	if target.DeviceIP != "" {
		risk += 15
	}

	switch target.Role {
	case "nurse":
		risk += 20
	case "billing":
		risk += 15
	}

	if risk > 40 {
		return 70.0
	}
	if risk > 20 {
		return 50.0
	}
	return 20.0
}

func getUptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	var seconds float64
	fmt.Sscanf(string(data), "%f", &seconds)
	return int64(seconds)
}
