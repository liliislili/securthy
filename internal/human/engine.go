package human

import (
	"go-scanner/internal/human/behavior"
	"go-scanner/internal/human/browser"
	"go-scanner/internal/human/data"
	"go-scanner/internal/human/email"
	"go-scanner/internal/human/identity"
	"go-scanner/internal/human/models"
	"go-scanner/internal/human/phishing"
	"go-scanner/internal/human/privilege"
	"go-scanner/internal/human/session"
	"go-scanner/internal/human/usb"
)

func RunHumanScan(target EmployeeTarget) HumanScanResult {

	// Convert to models.EmployeeTarget for sub-packages
	mt := models.EmployeeTarget{
		ID:       target.ID,
		Name:     target.Name,
		Email:    target.Email,
		DeviceIP: target.DeviceIP,
		Role:     target.Role,
	}

	wifiResult := behavior.ScanWiFi()
	wifiRisk := 20.0
	if wifiResult.HasOpen {
		wifiRisk = 95.0
	} else if wifiResult.HasWEP {
		wifiRisk = 85.0
	} else if wifiResult.HasWPA2 && !wifiResult.HasWPA3 {
		wifiRisk = 40.0
	} else if wifiResult.HasWPA3 {
		wifiRisk = 10.0
	}

	passwordRisk  := identity.Run(target.DeviceIP)
	phishingRisk  := phishing.Run(target.Email, target.DeviceIP)
	emailRisk     := email.Run(target.Email)
	sessionRisk   := session.Run(mt)
	privilegeRisk := privilege.Run(mt)
	usbRisk       := usb.Run(mt)
	browserRisk   := browser.Run(mt)
	dataRisk      := data.Run(mt)

	total := (phishingRisk * 0.20) +
		(passwordRisk * 0.20) +
		(wifiRisk * 0.15) +
		(emailRisk * 0.15) +
		(sessionRisk * 0.10) +
		(privilegeRisk * 0.10) +
		(usbRisk * 0.05) +
		(browserRisk * 0.03) +
		(dataRisk * 0.02)

	if total > 100 {
		total = 100
	}

	return HumanScanResult{
		EmployeeID: target.ID,
		Name:       target.Name,
		Role:       target.Role,
		Phishing:   phishingRisk,
		Password:   passwordRisk,
		WiFi:       wifiRisk,
		Email:      emailRisk,
		Session:    sessionRisk,
		Privilege:  privilegeRisk,
		USB:        usbRisk,
		Browser:    browserRisk,
		Data:       dataRisk,
		TotalRisk:  total,
		Grade:      GradeFromRisk(total),
	}
}
