package data

import (
	"os"
	"strings"

	"go-scanner/internal/human/models"
)

func Run(target models.EmployeeTarget) float64 {
	risk := 20.0

	home, _ := os.UserHomeDir()

	if fileExists(home + "/.config/Dropbox") {
		risk += 25
	}
	if fileExists(home + "/.config/Google/DriveFS") {
		risk += 25
	}
	if fileExists(home + "/Downloads") {
		risk += 10
	}
	if target.DeviceIP != "" && strings.HasPrefix(target.DeviceIP, "192.") {
		risk += 10
	}

	switch target.Role {
	case "doctor", "nurse":
		risk += 20
	case "billing":
		risk += 15
	}

	if risk > 60 {
		return 80.0
	}
	if risk > 30 {
		return 50.0
	}
	return 20.0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
