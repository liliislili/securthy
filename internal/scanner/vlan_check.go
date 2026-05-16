package scanner

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// VLANResult holds the result of segmentation testing for a network
type VLANResult struct {
	TestedFrom    string   // IP we're scanning from / the scanned host
	ReachableNets []string // subnets this host can reach
	Violations    []string // specific segmentation failures
	Score         int      // 0 = perfectly segmented, higher = worse
}

// ZoneType classifies a subnet into a hospital security zone
type ZoneType string

const (
	ZoneMedical  ZoneType = "medical-devices"      // DICOM/PACS/HL7
	ZoneClinical ZoneType = "clinical-workstation" // nurse/doctor PCs
	ZoneAdmin    ZoneType = "administrative"       // HR, billing
	ZoneGuest    ZoneType = "guest-wifi"
	ZoneInfra    ZoneType = "infrastructure" // switches, routers
	ZoneDatabase ZoneType = "database"
	ZoneUnknown  ZoneType = "unknown"
)

// KnownZones maps common private subnets to their typical hospital zone
// In a real engagement you'd ask the client for their VLAN map
var commonHospitalZones = map[string]ZoneType{
	"192.168.1":  ZoneClinical,
	"192.168.2":  ZoneMedical,
	"192.168.3":  ZoneAdmin,
	"192.168.4":  ZoneGuest,
	"192.168.10": ZoneMedical,
	"192.168.20": ZoneClinical,
	"192.168.30": ZoneAdmin,
	"192.168.40": ZoneGuest,
	"192.168.50": ZoneDatabase,
	"10.0.1":     ZoneClinical,
	"10.0.2":     ZoneMedical,
	"10.0.3":     ZoneAdmin,
	"10.0.10":    ZoneDatabase,
	"172.16.1":   ZoneClinical,
	"172.16.2":   ZoneMedical,
	"172.16.3":   ZoneAdmin,
}

// dangerousCrossings defines which zone pairs MUST NOT be able to communicate
var dangerousCrossings = [][2]ZoneType{
	{ZoneGuest, ZoneMedical},
	{ZoneGuest, ZoneClinical},
	{ZoneGuest, ZoneDatabase},
	{ZoneGuest, ZoneAdmin},
	{ZoneAdmin, ZoneMedical},
	{ZoneAdmin, ZoneDatabase},
}

// TestVLANSegmentation probes whether a host can reach IPs in other subnets
// It tries a quick TCP connect to common ports across different /24 subnets
func TestVLANSegmentation(sourceIP string, allDiscoveredIPs []string) VLANResult {
	result := VLANResult{TestedFrom: sourceIP}

	// Determine source zone
	sourceSubnet := subnet24(sourceIP)
	sourceZone := classifySubnet(sourceSubnet)

	// Collect unique subnets from all discovered hosts
	subnets := uniqueSubnets(allDiscoveredIPs)

	reachable := map[string]bool{}

	for _, subnet := range subnets {
		if subnet == sourceSubnet {
			continue
		}

		// Try to reach a host in this subnet
		// We probe the first few IPs in that range on common ports
		for lastOctet := 1; lastOctet <= 10; lastOctet++ {
			targetIP := fmt.Sprintf("%s.%d", subnet, lastOctet)
			if canReach(targetIP) {
				reachable[subnet] = true
				break
			}
		}
	}

	// Build reachable list
	for subnet := range reachable {
		result.ReachableNets = append(result.ReachableNets, subnet+".0/24")
	}
	sort.Strings(result.ReachableNets)

	// Check for dangerous crossings
	for subnet := range reachable {
		targetZone := classifySubnet(subnet)

		for _, crossing := range dangerousCrossings {
			fromZone, toZone := crossing[0], crossing[1]

			match := (sourceZone == fromZone && targetZone == toZone) ||
				(sourceZone == toZone && targetZone == fromZone)

			if match {
				violation := fmt.Sprintf(
					"CRITICAL: %s (%s) can reach %s.0/24 (%s) — VLAN segmentation FAILED",
					sourceIP, sourceZone, subnet, targetZone,
				)
				result.Violations = append(result.Violations, violation)
				result.Score += 20
			}
		}

		// Even crossing unknown zones from medical is a finding
		if sourceZone == ZoneMedical && targetZone == ZoneUnknown {
			result.Violations = append(result.Violations, fmt.Sprintf(
				"HIGH: Medical device %s can reach unknown subnet %s.0/24 — verify segmentation",
				sourceIP, subnet,
			))
			result.Score += 10
		}
	}

	return result
}

// canReach does a fast TCP connect to check reachability
func canReach(ip string) bool {
	probeports := []int{80, 22, 445, 443, 3389, 104}
	for _, port := range probeports {
		conn, err := net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", ip, port),
			300*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// subnet24 extracts the first three octets of an IP
func subnet24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) < 3 {
		return ip
	}
	return strings.Join(parts[:3], ".")
}

func classifySubnet(subnet string) ZoneType {
	if z, ok := commonHospitalZones[subnet]; ok {
		return z
	}
	return ZoneUnknown
}

func uniqueSubnets(ips []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, ip := range ips {
		s := subnet24(ip)
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// VLANSummary prints a human-readable segmentation summary
func VLANSummary(results []VLANResult) string {
	if len(results) == 0 {
		return "No VLAN segmentation data collected (single host scan)"
	}

	var sb strings.Builder
	violations := 0

	for _, r := range results {
		for _, v := range r.Violations {
			sb.WriteString("  [!] " + v + "\n")
			violations++
		}
	}

	if violations == 0 {
		return "VLAN segmentation appears intact — no dangerous cross-zone reachability detected"
	}

	return fmt.Sprintf("VLAN SEGMENTATION FAILURES: %d violation(s) found\n%s", violations, sb.String())
}
