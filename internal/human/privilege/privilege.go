package privilege

import (
	"os/user"

	"go-scanner/internal/human/models"
)

func Run(target models.EmployeeTarget) float64 {
	risk := 20.0

	u, err := user.Current()
	if err == nil {
		if u.Uid == "0" {
			risk += 40
		}
		if u.Username == "admin" {
			risk += 25
		}
	}

	switch target.Role {
	case "nurse":
		risk += 30
	case "billing":
		risk += 20
	case "doctor":
		risk += 10
	}

	if risk > 100 {
		return 100
	}
	if risk > 70 {
		return 80.0
	}
	if risk > 40 {
		return 60.0
	}
	return 30.0
}
