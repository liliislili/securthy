package usb

import (
	"os"
	"strings"

	"go-scanner/internal/human/models"
)

func Run(target models.EmployeeTarget) float64 {
	risk := 20.0

	data, err := os.ReadFile("/proc/mounts")
	if err == nil {
		content := string(data)
		if strings.Contains(content, "/media") || strings.Contains(content, "/mnt") {
			risk += 40
		}
	}

	switch target.Role {
	case "nurse", "billing":
		risk += 25
	case "doctor":
		risk += 15
	case "admin":
		risk += 10
	}

	if risk > 60 {
		return 85.0
	}
	if risk > 30 {
		return 55.0
	}
	return 25.0
}
