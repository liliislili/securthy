package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func init() {
	RegisterProbe(HTTPProbe{})
	RegisterProbe(SSHProbe{})
	RegisterProbe(SMTPProbe{})
	RegisterProbe(DICOMProbe{}) // ADD THIS
	RegisterProbe(HL7Probe{})   // ADD THIS
}

var commonPorts = map[int]string{

	// ===== Remote Access =====
	22:   "ssh",
	23:   "telnet", // insecure (important risk)
	3389: "rdp",

	// ===== Web Services =====
	80:   "http",
	443:  "https",
	8080: "http-alt",
	8443: "https-alt",

	// ===== File Sharing / Lateral Movement =====
	139:  "netbios",
	445:  "smb",
	2049: "nfs",

	// ===== Windows Infrastructure =====
	135: "rpc",
	137: "netbios-ns",
	138: "netbios-dgm",

	// ===== Directory / Authentication =====
	389: "ldap",
	636: "ldaps",
	88:  "kerberos",

	// ===== Email (sometimes present in hospital infra) =====
	25:  "smtp",
	110: "pop3",
	143: "imap",
	993: "imaps",
	995: "pop3s",

	// ===== Databases (CRITICAL in your project) =====
	3306:  "mysql",
	5432:  "postgresql",
	1433:  "mssql",
	27017: "mongodb",

	// ===== DNS / Network Core =====
	53: "dns",

	// ===== Medical Systems (VERY IMPORTANT for your project) =====
	104:  "dicom", // medical imaging (X-rays, MRI)
	2575: "hl7",   // health data exchange

	// ===== Monitoring / Logging =====
	514: "syslog",

	// ===== VPN / Secure Access =====
	1194: "openvpn",
	500:  "ipsec",

	// ===== Industrial / IoT (can appear in hospitals) =====
	502: "modbus",

	// ===== Misc but useful =====
	21:  "ftp",
	20:  "ftp-data",
	69:  "tftp",
	161: "snmp",
	162: "snmp-trap",
}

func GuessService(port int) string {
	service, ok := commonPorts[port]
	if ok {
		return service
	}
	return "unknown"
}
func ExtractVersion(banner string) string {
	parts := strings.Split(banner, "/")
	if len(parts) < 2 {
		return ""
	}

	v := strings.Fields(parts[1])[0]
	return strings.TrimSpace(v)
}

func GrabBanner(ip string, port int, timeout time.Duration) string {
	address := fmt.Sprintf("%s:%d", ip, port)

	// 1. Connect
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// 2. Set read timeout
	conn.SetReadDeadline(time.Now().Add(timeout))

	// 3. Prepare buffer
	buffer := make([]byte, 1024)

	// 4. Read data
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	// 5. Convert to string
	banner := string(buffer[:n])

	return banner
}
