package scanner

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type SNMPResult struct {
	Open           bool
	CommunityWorks []string // which community strings responded
	SystemDesc     string   // sysDescr — reveals OS, device type, version
	DeviceType     string   // inferred from sysDescr
	Vulnerable     bool
}

// Common SNMP community strings found on medical/network devices
var snmpCommunities = []string{
	"public",  // universal default — almost always works
	"private", // write access — critical if it responds
	"admin",
	"cisco",
	"community",
	"default",
	"internal",
	"monitor",
	"network",
	"snmp",
	"system",
	"manager",
}

// buildSNMPGetRequest builds a minimal SNMPv1 GET request for sysDescr (OID 1.3.6.1.2.1.1.1.0)
// This is raw ASN.1/BER encoding — no external library needed
func buildSNMPGetRequest(community string) []byte {
	// OID for sysDescr: 1.3.6.1.2.1.1.1.0
	oid, _ := hex.DecodeString("2b0601020101010")
	_ = oid

	comm := []byte(community)
	commLen := byte(len(comm))

	// Manually construct SNMPv1 GET request packet
	// Structure: Sequence { version, community, GetRequest-PDU { request-id, error, error-index, VarBindList } }
	varBind, _ := hex.DecodeString("302030120d2b060102010101000500") // sysDescr OID + null value
	varBindList := append([]byte{0x30, byte(len(varBind))}, varBind...)

	pdu := []byte{
		0xa0,                               // GetRequest-PDU tag
		byte(11 + len(varBindList)),        // length
		0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id = 1
		0x02, 0x01, 0x00, // error-status = 0
		0x02, 0x01, 0x00, // error-index = 0
	}
	pdu = append(pdu, varBindList...)

	// Recalculate PDU length
	pdu[1] = byte(len(pdu) - 2)

	msg := []byte{0x02, 0x01, 0x00}  // version = 0 (SNMPv1)
	msg = append(msg, 0x04, commLen) // community string tag + length
	msg = append(msg, comm...)
	msg = append(msg, pdu...)

	seq := []byte{0x30, byte(len(msg))}
	return append(seq, msg...)
}

// CheckSNMP sends SNMPv1 GET requests with common community strings
func CheckSNMP(ip string) SNMPResult {
	result := SNMPResult{}

	addr := fmt.Sprintf("%s:161", ip)

	for _, community := range snmpCommunities {
		packet := buildSNMPGetRequest(community)

		conn, err := net.DialTimeout("udp", addr, 2*time.Second)
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write(packet)
		if err != nil {
			conn.Close()
			continue
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil && n > 0 {
			result.Open = true
			result.Vulnerable = true
			result.CommunityWorks = append(result.CommunityWorks, community)

			// Try to extract sysDescr string from response
			// It's an OCTET STRING somewhere in the ASN.1 response
			desc := extractOctetString(buf[:n])
			if desc != "" && result.SystemDesc == "" {
				result.SystemDesc = desc
				result.DeviceType = inferDeviceType(desc)
			}
		}
	}

	return result
}

// extractOctetString finds the first readable string in a raw SNMP response
func extractOctetString(data []byte) string {
	for i := 0; i < len(data)-2; i++ {
		// OCTET STRING tag = 0x04
		if data[i] == 0x04 && int(data[i+1]) > 4 && i+2+int(data[i+1]) <= len(data) {
			strLen := int(data[i+1])
			s := string(data[i+2 : i+2+strLen])
			// Only return if it looks like readable text
			if isPrintable(s) && len(s) > 4 {
				return s
			}
		}
	}
	return ""
}

func isPrintable(s string) bool {
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func inferDeviceType(sysDescr string) string {
	d := strings.ToLower(sysDescr)
	switch {
	case strings.Contains(d, "windows"):
		return "Windows workstation/server"
	case strings.Contains(d, "linux"):
		return "Linux system"
	case strings.Contains(d, "cisco"):
		return "Cisco network device"
	case strings.Contains(d, "hp") || strings.Contains(d, "hewlett"):
		return "HP device/printer"
	case strings.Contains(d, "siemens"):
		return "Siemens medical device"
	case strings.Contains(d, "dicom") || strings.Contains(d, "pacs"):
		return "Medical imaging system"
	case strings.Contains(d, "printer") || strings.Contains(d, "jetdirect"):
		return "Network printer"
	case strings.Contains(d, "switch") || strings.Contains(d, "router"):
		return "Network infrastructure"
	default:
		return "Unknown device"
	}
}

// SNMPFinding returns human-readable risk findings from SNMP result
func SNMPFinding(r SNMPResult, ip string) []string {
	var findings []string
	if !r.Vulnerable {
		return findings
	}

	for _, c := range r.CommunityWorks {
		sev := "HIGH"
		if c == "private" {
			sev = "CRITICAL" // private = write access to device
		}
		findings = append(findings,
			fmt.Sprintf("%s: SNMP community '%s' accepted on %s — device info exposed", sev, c, ip))
	}

	if r.SystemDesc != "" {
		findings = append(findings,
			fmt.Sprintf("INFO: Device identifies as: %s", r.SystemDesc))
	}

	if r.DeviceType != "" {
		findings = append(findings,
			fmt.Sprintf("INFO: Device type inferred: %s", r.DeviceType))
	}

	return findings
}
