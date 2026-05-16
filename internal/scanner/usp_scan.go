package scanner

import (
	"fmt"
	"net"
	"time"
)

type UDPResult struct {
	Port    int
	Open    bool
	Service string
	Banner  string
}

// UDP probes — each sends a protocol-specific payload that triggers a response
// UDP is connectionless so silence ≠ closed, we need a real response to confirm open

var udpProbes = map[int]struct {
	payload []byte
	service string
}{
	// DNS — query for "." (root) type ANY
	53: {
		payload: []byte{
			0x00, 0x01, // Transaction ID
			0x01, 0x00, // Flags: standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answers: 0
			0x00, 0x00, // Authority: 0
			0x00, 0x00, // Additional: 0
			0x00,       // Root label
			0x00, 0xff, // Type: ANY
			0x00, 0x01, // Class: IN
		},
		service: "dns",
	},
	// SNMP — SNMPv1 GET sysDescr with community "public"
	161: {
		payload: []byte{
			0x30, 0x26, // Sequence
			0x02, 0x01, 0x00, // version: 0 (SNMPv1)
			0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // community: "public"
			0xa0, 0x19, // GetRequest-PDU
			0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id
			0x02, 0x01, 0x00, // error-status: 0
			0x02, 0x01, 0x00, // error-index: 0
			0x30, 0x0b, // VarBindList
			0x30, 0x09, // VarBind
			0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID: 1.3.6.1.2.1 (mib-2)
			0x05, 0x00, // Value: NULL
		},
		service: "snmp",
	},
	// NTP — version request
	123: {
		payload: []byte{
			0x1b, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		service: "ntp",
	},
	// Syslog — RFC 5424 test message
	514: {
		payload: []byte("<34>1 - - - - - - test syslog probe\n"),
		service: "syslog",
	},
	// TFTP — read request for a nonexistent file (will get error response)
	69: {
		payload: []byte{
			0x00, 0x01, // Opcode: RRQ (read request)
			0x74, 0x65, 0x73, 0x74, 0x00, // filename: "test\0"
			0x6f, 0x63, 0x74, 0x65, 0x74, 0x00, // mode: "octet\0"
		},
		service: "tftp",
	},
}

// ScanUDP scans a list of UDP ports on a target IP
// Returns only confirmed open ports (those that sent a response)
func ScanUDP(ip string, ports []int) []UDPResult {
	var results []UDPResult

	for _, port := range ports {
		probe, known := udpProbes[port]
		if !known {
			continue // skip ports we don't have a probe for
		}

		result := probeUDP(ip, port, probe.payload, probe.service)
		if result.Open {
			results = append(results, result)
		}
	}

	return results
}

func probeUDP(ip string, port int, payload []byte, service string) UDPResult {
	result := UDPResult{Port: port, Service: service}

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	_, err = conn.Write(payload)
	if err != nil {
		return result
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		// Timeout or no response = filtered or closed for UDP
		// We only confirm open if we got a real response
		return result
	}

	if n > 0 {
		result.Open = true
		result.Banner = parseUDPBanner(port, buf[:n])
	}

	return result
}

func parseUDPBanner(port int, data []byte) string {
	switch port {
	case 53:
		if len(data) > 4 {
			return fmt.Sprintf("DNS server responded (%d bytes) — DNS amplification risk", len(data))
		}
	case 161:
		if len(data) > 2 {
			// Try to extract community string from SNMP response
			desc := extractOctetString(data)
			if desc != "" {
				return fmt.Sprintf("SNMP responded: %s", desc)
			}
			return fmt.Sprintf("SNMP responded (%d bytes)", len(data))
		}
	case 123:
		if len(data) >= 4 {
			stratum := data[1]
			return fmt.Sprintf("NTP server (stratum %d)", stratum)
		}
	case 514:
		return "Syslog port accepting data — log injection possible"
	case 69:
		return "TFTP server active — unauthenticated file transfer possible"
	}
	return fmt.Sprintf("responded (%d bytes)", len(data))
}

// UDPHealthcarePorts are the UDP ports most relevant to hospital networks
var UDPHealthcarePorts = []int{
	53,  // DNS
	69,  // TFTP — often used to update medical device firmware
	123, // NTP — time sync
	161, // SNMP — device management
	514, // Syslog
}

// UDPFindings returns risk findings for UDP results
func UDPFindings(results []UDPResult, ip string) []string {
	var findings []string

	for _, r := range results {
		if !r.Open {
			continue
		}
		switch r.Port {
		case 161:
			findings = append(findings,
				fmt.Sprintf("HIGH: SNMP UDP/161 confirmed open on %s — %s", ip, r.Banner))
		case 69:
			findings = append(findings,
				fmt.Sprintf("HIGH: TFTP UDP/69 open on %s — unauthenticated firmware/file access possible", ip))
		case 514:
			findings = append(findings,
				fmt.Sprintf("MEDIUM: Syslog UDP/514 open on %s — log injection or info leak possible", ip))
		case 53:
			findings = append(findings,
				fmt.Sprintf("INFO: DNS UDP/53 open on %s — %s", ip, r.Banner))
		case 123:
			findings = append(findings,
				fmt.Sprintf("INFO: NTP UDP/123 open on %s — %s", ip, r.Banner))
		}
	}

	return findings
}
