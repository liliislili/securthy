package browser

import (
	"os"
	"strings"

	"go-scanner/internal/human/models"
)

func Run(target models.EmployeeTarget) float64 {
	risk := 20.0

	home, err := os.UserHomeDir()
	if err != nil {
		return 40.0
	}

	if fileExists(home + "/.config/google-chrome/Default/Login Data") {
		risk += 30
	}
	if strings.Contains(home, ".mozilla") {
		risk += 20
	}
	if fileExists(home + "/.config/google-chrome/Default/Extensions") {
		risk += 20
	}

	switch target.Role {
	case "billing", "admin":
		risk += 15
	}

	if risk > 60 {
		return 75.0
	}
	if risk > 35 {
		return 55.0
	}
	return 25.0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
