package main

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Loopback IPs we need — one per simulated device
var loopbackIPs = []string{
	"127.0.0.10",
	"127.0.0.11",
	"127.0.0.20",
	"127.0.0.21",
	"127.0.0.30",
	"127.0.0.31",
	"127.0.0.32",
	"127.0.0.33",
	"127.0.0.40",
	"127.0.0.41",
	"127.0.0.50",
	"127.0.0.51",
}

// setupLoopbackAliases adds 127.0.0.x addresses to the loopback interface
// These are already routable on Linux — we just need to assign them
func setupLoopbackAliases() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("only Linux supported for loopback aliases")
	}

	for _, ip := range loopbackIPs {
		// Check if already exists
		if loopbackExists(ip) {
			continue
		}

		cmd := exec.Command("ip", "addr", "add", ip+"/8", "dev", "lo")
		out, err := cmd.CombinedOutput()
		if err != nil {
			// "RTNETLINK answers: File exists" means it's already there — OK
			if strings.Contains(string(out), "File exists") {
				continue
			}
			return fmt.Errorf("ip addr add %s failed: %s — try running simulator with sudo", ip, string(out))
		}
	}

	return nil
}

// loopbackExists checks if an IP is already assigned to lo
func loopbackExists(ip string) bool {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if strings.HasPrefix(addr.String(), ip+"/") {
			return true
		}
	}
	return false
}

// cleanupLoopbackAliases removes the added aliases on shutdown
func cleanupLoopbackAliases() {
	for _, ip := range loopbackIPs {
		exec.Command("ip", "addr", "del", ip+"/8", "dev", "lo").Run()
	}
	fmt.Println("[*] Loopback aliases cleaned up.")
}

// ── Single-host fallback mode ─────────────────────────────────────────────────
// If we can't add loopback aliases (no sudo), run everything on 127.0.0.1
// using high port numbers to simulate different devices

type PortMapping struct {
	OriginalIP   string
	DeviceName   string
	OriginalPort int
	MappedPort   int
}

var singleHostMappings []PortMapping

func runSingleHostMode() {
	fmt.Println()
	fmt.Println("[*] Single-host mode: all devices simulated on 127.0.0.1")
	fmt.Println("[*] Ports are shifted per device to avoid conflicts:")
	fmt.Println()

	// Port shift per device: device index * 1000
	// e.g. device 0 (firewall): port 22 → 10022
	//      device 1 (switch):   port 23 → 11023
	//      device 2 (DEM):      port 8080 → 12080

	started := 0
	for i, device := range devices {
		shift := (i + 10) * 1000 // 10000, 11000, 12000 ...
		for _, svc := range device.Services {
			if svc.UDP {
				continue // skip UDP in single-host mode
			}
			mappedPort := shift + svc.Port
			if mappedPort > 65535 {
				continue
			}

			mapping := PortMapping{
				OriginalIP:   device.IP,
				DeviceName:   device.Name,
				OriginalPort: svc.Port,
				MappedPort:   mappedPort,
			}
			singleHostMappings = append(singleHostMappings, mapping)

			handler := svc.Handler
			go func(port int, h func(net.Conn)) {
				listenTCP("127.0.0.1", port, h)
			}(mappedPort, handler)
			started++
		}
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)
	printSingleHostTable()
	waitForInterrupt()
}

func printSingleHostTable() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  SINGLE-HOST MODE — all devices on 127.0.0.1                    ║")
	fmt.Println("╠══════════════╦══════════╦══════════╦════════════════════════════╣")
	fmt.Printf("║ %-12s ║ %-8s ║ %-8s ║ %-26s ║\n", "Device IP", "Orig Port", "Test Port", "Device")
	fmt.Println("╠══════════════╬══════════╬══════════╬════════════════════════════╣")
	for _, m := range singleHostMappings {
		fmt.Printf("║ %-12s ║ %-8d ║ %-8d ║ %-26s ║\n",
			m.OriginalIP, m.OriginalPort, m.MappedPort, truncate(m.DeviceName, 26))
	}
	fmt.Println("╚══════════════╩══════════╩══════════╩════════════════════════════╝")
	fmt.Println()
	fmt.Println("  To test a specific service, use netcat:")
	fmt.Println("  nc 127.0.0.1 <test_port>")
	fmt.Println()
	fmt.Println("  Example — test DEM FHIR (original port 8080, mapped to 12080):")
	fmt.Println("  curl http://127.0.0.1:12080/fhir/Patient")
	fmt.Println()
	fmt.Println("  Note: full subnet scan won't work in this mode.")
	fmt.Println("  Re-run with sudo for the full multi-IP simulation.")
	fmt.Println()
}

func waitForInterrupt() {
	fmt.Println("Press Ctrl+C to stop simulator...")
	select {} // block forever until signal
}
