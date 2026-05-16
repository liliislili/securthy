package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Fingerprint struct {
	OS         string
	DeviceType string
	Vendor     string
	Confidence string // "high", "medium", "low"
}

// FingerprintHost tries to identify the OS and device type
// by analyzing banners from open ports
func FingerprintHost(ip string, banners map[int]string) Fingerprint {
	fp := Fingerprint{OS: "unknown", DeviceType: "unknown", Confidence: "low"}

	combined := strings.ToLower(strings.Join(mapValues(banners), " "))

	// Windows fingerprinting
	if strings.Contains(combined, "windows") || strings.Contains(combined, "microsoft") || strings.Contains(combined, "iis") {
		fp.OS = "Windows"
		fp.Confidence = "high"
		if strings.Contains(combined, "windows xp") || strings.Contains(combined, "5.1") {
			fp.OS = "Windows XP (END OF LIFE - CRITICAL)"
			fp.DeviceType = "legacy-workstation"
		} else if strings.Contains(combined, "windows 7") || strings.Contains(combined, "6.1") {
			fp.OS = "Windows 7 (END OF LIFE)"
			fp.DeviceType = "workstation"
		} else if strings.Contains(combined, "server 2008") {
			fp.OS = "Windows Server 2008 (END OF LIFE)"
			fp.DeviceType = "server"
		}
	}

	// Linux fingerprinting
	if strings.Contains(combined, "ubuntu") {
		fp.OS = "Ubuntu Linux"
		fp.Confidence = "high"
	} else if strings.Contains(combined, "debian") {
		fp.OS = "Debian Linux"
		fp.Confidence = "high"
	} else if strings.Contains(combined, "linux") {
		fp.OS = "Linux"
		fp.Confidence = "medium"
	}

	// Medical device fingerprinting
	if strings.Contains(combined, "dicom") || strings.Contains(combined, "pacs") {
		fp.DeviceType = "medical-imaging (PACS/DICOM)"
		fp.Confidence = "high"
	}
	if strings.Contains(combined, "hl7") || strings.Contains(combined, "mllp") {
		fp.DeviceType = "healthcare-integration-engine"
		fp.Confidence = "high"
	}

	// Vendor fingerprinting from SSH banners
	if strings.Contains(combined, "cisco") {
		fp.Vendor = "Cisco"
		fp.DeviceType = "network-equipment"
	} else if strings.Contains(combined, "siemens") {
		fp.Vendor = "Siemens Healthineers"
		fp.DeviceType = "medical-device"
	} else if strings.Contains(combined, "philips") {
		fp.Vendor = "Philips Healthcare"
		fp.DeviceType = "medical-device"
	} else if strings.Contains(combined, "ge ") || strings.Contains(combined, "gehealthcare") {
		fp.Vendor = "GE Healthcare"
		fp.DeviceType = "medical-device"
	}

	// TTL-based OS hint via TCP probe
	ttlOS := probeTTL(ip)
	if fp.OS == "unknown" && ttlOS != "" {
		fp.OS = ttlOS
		fp.Confidence = "low"
	}

	return fp
}

// probeTTL makes a TCP connection and infers OS from typical TTL values
func probeTTL(ip string) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 1*time.Second)
	if err != nil {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip), 1*time.Second)
		if err != nil {
			return ""
		}
	}
	defer conn.Close()

	// We can't directly read TTL from net.Conn in pure Go without raw sockets
	// So we rely purely on banner analysis above
	// This is a placeholder for future raw socket implementation
	return ""
}

func mapValues(m map[int]string) []string {
	vals := make([]string, 0, len(m))
	for _, v := range m {
		vals = append(vals, v)
	}
	return vals
}
