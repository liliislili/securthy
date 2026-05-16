package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ── SSH ───────────────────────────────────────────────────────────────────────

func sshBanner(version string) func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "SSH-2.0-%s\r\n", version)
		// Read client hello (ignore it)
		buf := make([]byte, 256)
		conn.Read(buf)
	}
}

// ── HTTP (plain) ───────────────────────────────────────────────────────────────

func httpBanner(serverHeader string) func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1024)
		conn.Read(buf)
		body := "<html><body><h1>Hospital Portal</h1></body></html>"
		fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s",
			serverHeader, len(body), body)
	}
}

// ── HTTP admin panel with exploitable default creds ────────────────────────────

func httpAdminPanel(title, user, pass string) func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, _ := conn.Read(buf)
		request := string(buf[:n])

		serverVersion := "Apache/2.4.41"
		if strings.Contains(strings.ToLower(title), "orthanc") {
			serverVersion = "Orthanc/1.9.0"
		} else if strings.Contains(strings.ToLower(title), "dem") {
			serverVersion = "nginx/1.14.2"
		}

		// Check for Basic Auth header
		authed := false
		if strings.Contains(request, "Authorization: Basic") {
			// Decode and check
			for _, line := range strings.Split(request, "\r\n") {
				if strings.HasPrefix(line, "Authorization: Basic ") {
					encoded := strings.TrimPrefix(line, "Authorization: Basic ")
					decoded := decodeBase64Simple(encoded)
					if decoded == user+":"+pass {
						authed = true
					}
				}
			}
		}

		if authed || strings.Contains(request, "GET /admin") || strings.Contains(request, "GET / ") {
			body := fmt.Sprintf(`<html><body><h1>%s</h1><p>Welcome, admin</p></body></html>`, title)
			fmt.Fprintf(conn,
				"HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s",
				serverVersion, len(body), body)
		} else {
			body := fmt.Sprintf(`<html><body><h1>%s — Login</h1></body></html>`, title)
			fmt.Fprintf(conn,
				"HTTP/1.1 401 Unauthorized\r\nServer: %s\r\nWWW-Authenticate: Basic realm=\"%s\"\r\nContent-Length: %d\r\n\r\n%s",
				serverVersion, title, len(body), body)
		}
	}
}

// ── HTTPS (simulated — just sends HTTP, no real TLS) ──────────────────────────

func httpsHandler(title string, expired bool) func(net.Conn) {
	// In the simulator we just serve HTTP on the HTTPS port
	// The scanner's TLS check will correctly report "TLS not available"
	// which is itself a finding for port 443
	return httpBanner("nginx/1.18.0 " + title)
}

// ── FHIR server (DEM) — unauthenticated ───────────────────────────────────────

func fhirServer() func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, _ := conn.Read(buf)
		request := string(buf[:n])

		serverHdr := "DEM-FHIR/2.1.0 (Algeria)"

		if strings.Contains(request, "/fhir/Patient") || strings.Contains(request, "/dem/Patient") {
			// VULNERABILITY: returns patient data with no auth check
			body := `{
  "resourceType": "Bundle",
  "type": "searchset",
  "total": 3,
  "entry": [
    {
      "resourceType": "Patient",
      "id": "pat-001",
      "name": [{"family": "BENALI", "given": ["Mohamed"]}],
      "birthDate": "1975-03-12",
      "identifier": [{"system": "urn:dem:algeria", "value": "DEM-00123456"}]
    },
    {
      "resourceType": "Patient",
      "id": "pat-002",
      "name": [{"family": "KHELIFI", "given": ["Fatima"]}],
      "birthDate": "1990-07-22",
      "identifier": [{"system": "urn:dem:algeria", "value": "DEM-00234567"}]
    }
  ]
}`
			fmt.Fprintf(conn,
				"HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: application/fhir+json\r\nContent-Length: %d\r\n\r\n%s",
				serverHdr, len(body), body)
			return
		}

		if strings.Contains(request, "/fhir/metadata") || strings.Contains(request, "/dem/metadata") {
			body := `{
  "resourceType": "CapabilityStatement",
  "status": "active",
  "fhirVersion": "4.0.1",
  "software": {"name": "DEM Algeria FHIR Server", "version": "2.1.0"},
  "rest": [{"mode": "server", "security": {"cors": true}}]
}`
			fmt.Fprintf(conn,
				"HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: application/fhir+json\r\nContent-Length: %d\r\n\r\n%s",
				serverHdr, len(body), body)
			return
		}

		// Default
		body := `{"resourceType":"OperationOutcome"}`
		fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: application/fhir+json\r\nContent-Length: %d\r\n\r\n%s",
			serverHdr, len(body), body)
	}
}

// ── HL7 MLLP server ───────────────────────────────────────────────────────────

func hl7Server() func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1024)
		conn.Read(buf)

		// Send HL7 ACK wrapped in MLLP framing
		hl7Ack := "MSH|^~\\&|DEM-ALGERIA|CHU-TLEMCEN|SCANNER|SCANNER|" +
			time.Now().Format("20060102150405") +
			"||ACK^A01|1|P|2.5\rMSA|AA|1|Message received\r"

		mllpStart := byte(0x0B)
		mllpEnd := []byte{0x1C, 0x0D}

		response := append([]byte{mllpStart}, []byte(hl7Ack)...)
		response = append(response, mllpEnd...)
		conn.Write(response)
	}
}

// ── DICOM server ──────────────────────────────────────────────────────────────

func dicomServer() func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 512)
		conn.Read(buf)

		// Send A-ASSOCIATE-AC (accepted) — PDU type 0x02
		// This means: yes, I accept your DICOM association, no auth needed
		assocAC := []byte{
			0x02, 0x00, // PDU type: A-ASSOCIATE-AC
			0x00, 0x00, 0x00, 0x1c, // PDU length
			0x00, 0x01, // Protocol version
			0x00, 0x00, // Reserved
			// Called AE Title (16 bytes padded)
			0x50, 0x41, 0x43, 0x53, 0x2d, 0x41, 0x4c, 0x47,
			0x45, 0x52, 0x49, 0x41, 0x20, 0x20, 0x20, 0x20,
			// Calling AE Title (16 bytes padded)
			0x53, 0x43, 0x41, 0x4e, 0x4e, 0x45, 0x52, 0x20,
			0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		}
		conn.Write(assocAC)
	}
}

// ── TELNET — no authentication ────────────────────────────────────────────────

func telnetNoAuth(deviceName string) func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		// Telnet IAC negotiation
		conn.Write([]byte{0xff, 0xfb, 0x03, 0xff, 0xfb, 0x01}) // WILL SUPPRESS-GO-AHEAD, WILL ECHO
		// Send banner then immediately drop to shell
		fmt.Fprintf(conn, "\r\n%s\r\n\r\n# ", deviceName)
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(string(buf[:n]))
			if cmd != "" {
				fmt.Fprintf(conn, "\r\n%s: command not found\r\n# ", cmd)
			}
		}
	}
}

// ── TELNET — with login prompt ────────────────────────────────────────────────

func telnetWithLogin() func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		conn.Write([]byte{0xff, 0xfb, 0x03})
		fmt.Fprintf(conn, "\r\nHospital Workstation\r\nlogin: ")
		buf := make([]byte, 128)
		conn.Read(buf) // username
		fmt.Fprintf(conn, "Password: ")
		conn.Read(buf) // password
		fmt.Fprintf(conn, "\r\nLogin incorrect\r\n")
	}
}

// ── FTP with default credentials ──────────────────────────────────────────────

func ftpDefaultCreds(user, pass string) func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		fmt.Fprintf(conn, "220 Hospital FTP Server (ProFTPd 1.3.5)\r\n")
		buf := make([]byte, 256)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(string(buf[:n]))
			parts := strings.SplitN(cmd, " ", 2)
			verb := strings.ToUpper(parts[0])
			arg := ""
			if len(parts) > 1 {
				arg = parts[1]
			}

			switch verb {
			case "USER":
				if arg == user || user == "" {
					fmt.Fprintf(conn, "331 Password required\r\n")
				} else {
					fmt.Fprintf(conn, "331 Password required\r\n")
				}
			case "PASS":
				if arg == pass || pass == "" {
					fmt.Fprintf(conn, "230 User logged in\r\n") // SUCCESS
				} else {
					fmt.Fprintf(conn, "530 Login incorrect\r\n")
					return
				}
			case "QUIT":
				fmt.Fprintf(conn, "221 Goodbye\r\n")
				return
			default:
				fmt.Fprintf(conn, "500 Unknown command\r\n")
			}
		}
	}
}

// ── SMB — no signing ─────────────────────────────────────────────────────────

func smbNoSigning(version string) func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil || n < 4 {
			return
		}

		// Check if client sent SMB2 negotiate
		if n > 8 && buf[4] == 0xfe && buf[5] == 'S' {
			// SMB2 Negotiate Response
			// SecurityMode = 0x01 (signing enabled but NOT required)
			resp := make([]byte, 0, 128)
			// NetBIOS header
			resp = append(resp, 0x00, 0x00, 0x00, 0x00) // length placeholder

			// SMB2 header (64 bytes)
			resp = append(resp, 0xfe, 0x53, 0x4d, 0x42)                         // SMB2 magic
			resp = append(resp, 0x40, 0x00)                                     // StructureSize
			resp = append(resp, 0x00, 0x00)                                     // CreditCharge
			resp = append(resp, 0x00, 0x00, 0x00, 0x00)                         // Status: SUCCESS
			resp = append(resp, 0x00, 0x00)                                     // Command: Negotiate
			resp = append(resp, 0x01, 0x00)                                     // CreditResponse
			resp = append(resp, 0x01, 0x00, 0x00, 0x00)                         // Flags: response
			resp = append(resp, 0x00, 0x00, 0x00, 0x00)                         // NextCommand
			resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // MessageId
			resp = append(resp, 0x00, 0x00, 0x00, 0x00)                         // Reserved
			resp = append(resp, 0x00, 0x00, 0x00, 0x00)                         // TreeId
			resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // SessionId
			resp = append(resp, make([]byte, 16)...)                            // Signature

			// Negotiate response body
			resp = append(resp, 0x41, 0x00)    // StructureSize: 65
			dialectBytes := []byte{0x10, 0x02} // SMB 2.1
			if version == "SMBv3" {
				dialectBytes = []byte{0x00, 0x03} // SMB 3.0
			}
			resp = append(resp, dialectBytes...)
			resp = append(resp,
				0x01, 0x00, // SecurityMode: 0x01 = signing ENABLED but NOT required
				0x00, 0x00, // Reserved
				0x7f, 0x00, 0x00, 0x00, // Capabilities
			)
			resp = append(resp, make([]byte, 16)...)                            // ServerGuid
			resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // SystemTime
			resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // ServerStartTime
			resp = append(resp, 0x00, 0x00)                                     // SecurityBufferOffset
			resp = append(resp, 0x00, 0x00)                                     // SecurityBufferLength
			resp = append(resp, 0x00, 0x00, 0x00, 0x00)                         // NegotiateContextOffset

			// Fix NetBIOS length
			binary.BigEndian.PutUint32(resp[0:4], uint32(len(resp)-4))
			conn.Write(resp)
		}
	}
}

// ── SMB v1 — EternalBlue era ──────────────────────────────────────────────────

func smbV1() func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n < 4 {
			return
		}

		// Respond with SMBv1 Negotiate Response
		smbv1Resp := []byte{
			0x00, 0x00, 0x00, 0x55, // NetBIOS length
			0xff, 0x53, 0x4d, 0x42, // SMBv1 magic \xffSMB
			0x72,                   // Command: Negotiate
			0x00, 0x00, 0x00, 0x00, // Status: SUCCESS
			0x88,       // Flags
			0x01, 0xc8, // Flags2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sig + reserved
			0x00, 0x00, // TreeID
			0xff, 0xff, // PID
			0x00, 0x00, // UID
			0x01, 0x00, // MID
			// WordCount and parameters
			0x11,
			0x00, 0x00, // DialectIndex: 0 (NT LM 0.12)
			0x03,       // SecurityMode: no signing required
			0x00, 0x01, // MaxMpxCount
			0x00, 0x01, // MaxNumberVcs
			0x00, 0x00, 0x10, 0x00, // MaxBufferSize
			0x00, 0x00, 0x00, 0x00, // MaxRawSize
			0x00, 0x00, 0x00, 0x00, // SessionKey
			0x01, 0x00, 0x00, 0x00, // Capabilities
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SystemTime
			0x00, 0x00, // ServerTimeZone
			0x08, // ChallengeLength
			0x00, 0x00,
		}
		conn.Write(smbv1Resp)
	}
}

// ── RDP — no NLA ─────────────────────────────────────────────────────────────

func rdpNoNLA() func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		conn.Read(buf)

		// X.224 Connection Confirm — selected protocol = 0 (no NLA, no SSL)
		rdpResp := []byte{
			0x03, 0x00, 0x00, 0x13, // TPKT header, length 19
			0x0e,       // X.224 TPDU length
			0xd0,       // X.224 Connection Confirm
			0x00, 0x00, // DST-REF
			0x00, 0x00, // SRC-REF
			0x00,       // Class
			0x02,       // Type: RDP_NEG_RSP
			0x00,       // Flags
			0x08, 0x00, // Length
			0x00, 0x00, 0x00, 0x00, // Selected protocol: 0 = PROTOCOL_RDP (no NLA!)
		}
		conn.Write(rdpResp)
	}
}

// ── Database banners ──────────────────────────────────────────────────────────

func mysqlBanner() func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		// MySQL server greeting packet
		greeting := []byte{
			0x4a, 0x00, 0x00, 0x00, // packet length + sequence
			0x0a, // protocol version 10
		}
		// Server version string
		greeting = append(greeting, []byte("5.7.38-log\x00")...)
		// Connection ID (4 bytes)
		greeting = append(greeting, 0x01, 0x00, 0x00, 0x00)
		// Auth plugin data part 1 (8 bytes) + filler
		greeting = append(greeting, []byte("aB3cD4eF\x00")...)
		// Capability flags, charset, status, more capability flags
		greeting = append(greeting,
			0xff, 0xf7, // capability flags low
			0x21,       // charset: utf8
			0x02, 0x00, // status: autocommit
			0xff, 0x81, // capability flags high
			0x15, // auth plugin data length
		)
		greeting = append(greeting, make([]byte, 10)...) // reserved
		greeting = append(greeting, []byte("aB3cD4eFgH123456\x00")...)
		greeting = append(greeting, []byte("mysql_native_password\x00")...)

		// Fix length header
		binary.LittleEndian.PutUint32(greeting[0:4], uint32(len(greeting)-4))
		greeting[3] = 0 // sequence number
		conn.Write(greeting)
	}
}

func mssqlBanner() func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 256)
		conn.Read(buf)
		// TDS pre-login response
		resp := []byte{
			0x04, 0x01, 0x00, 0x25, 0x00, 0x00, 0x01, 0x00,
			0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
			0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
			0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
			0x01, 0xff,
			0x0e, 0x00, 0x0c, 0x00, // version: SQL Server 2014
			0x00, 0x00,
		}
		conn.Write(resp)
	}
}

func modbusBanner() func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n >= 6 {
			// Echo back a valid Modbus response (function code = request function code)
			resp := make([]byte, 6)
			copy(resp, buf[:2]) // transaction ID
			resp[2] = 0x00      // protocol
			resp[3] = 0x00
			resp[4] = 0x00                            // length high
			resp[5] = 0x03                            // length low
			resp = append(resp, buf[6], buf[7], 0x00) // unit ID, function, data
			conn.Write(resp)
		}
	}
}

// ── SNMP ─────────────────────────────────────────────────────────────────────

func snmpPublic(sysDescr string) func(net.Conn) {
	return func(conn net.Conn) {
		// This is called from the UDP handler, conn is nil
		// Actual response is in handleUDPPacket
	}
}

// handleUDPPacket handles incoming UDP packets (mainly SNMP)
func handleUDPPacket(conn net.PacketConn, remote net.Addr, data []byte, port int) {
	if port != 161 {
		return
	}

	// Check if it's an SNMP request with community "public" or "private"
	payload := string(data)
	isPublic := strings.Contains(payload, "public")
	isPrivate := strings.Contains(payload, "private")

	if !isPublic && !isPrivate {
		return // ignore unknown community strings
	}

	// Find the sysDescr for this IP from devices list
	// Extract destination IP from local addr
	localAddr := conn.LocalAddr().String()
	targetIP := strings.Split(localAddr, ":")[0]
	sysDescr := getSysDescrForIP(targetIP)

	// Build SNMP response with sysDescr
	community := "public"
	if isPrivate {
		community = "private"
	}

	response := buildSNMPResponse(community, sysDescr, data)
	conn.WriteTo(response, remote)
}

func getSysDescrForIP(ip string) string {
	for _, d := range devices {
		if d.IP == ip {
			for _, svc := range d.Services {
				if svc.Port == 161 {
					// Extract sysDescr from closure — we use device name instead
					return d.Name + " — " + d.Role
				}
			}
		}
	}
	return "Unknown Device"
}

func buildSNMPResponse(community, sysDescr string, request []byte) []byte {
	comm := []byte(community)
	desc := []byte(sysDescr)

	// Get request ID from request (bytes 10-13 in the PDU)
	reqID := []byte{0x00, 0x00, 0x00, 0x01}
	if len(request) > 18 {
		reqID = request[14:18]
	}

	// Build VarBind: OID sysDescr + OCTET STRING value
	varBind := []byte{0x30}
	oidBytes, _ := encodeSNMPOID("1.3.6.1.2.1.1.1.0")
	inner := append(oidBytes, 0x04, byte(len(desc)))
	inner = append(inner, desc...)
	varBind = append(varBind, byte(len(inner)))
	varBind = append(varBind, inner...)

	// VarBindList
	varBindList := append([]byte{0x30, byte(len(varBind))}, varBind...)

	// GetResponse PDU
	pdu := []byte{0xa2, byte(len(varBindList) + 10)}
	pdu = append(pdu, 0x02, 0x04)
	pdu = append(pdu, reqID...)
	pdu = append(pdu, 0x02, 0x01, 0x00) // error-status
	pdu = append(pdu, 0x02, 0x01, 0x00) // error-index
	pdu = append(pdu, varBindList...)

	// Full message
	msg := []byte{0x02, 0x01, 0x00} // version
	msg = append(msg, 0x04, byte(len(comm)))
	msg = append(msg, comm...)
	msg = append(msg, pdu...)

	seq := []byte{0x30, byte(len(msg))}
	return append(seq, msg...)
}

func encodeSNMPOID(oid string) ([]byte, error) {
	// Minimal: return pre-encoded sysDescr OID 1.3.6.1.2.1.1.1.0
	return []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}, nil
}

// ── Generic handler ───────────────────────────────────────────────────────────

func genericBannerHandler(banner string) func(net.Conn) {
	return func(conn net.Conn) {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte(banner + "\r\n"))
		buf := make([]byte, 64)
		conn.Read(buf)
	}
}

// ── Base64 decode (minimal, for HTTP auth) ────────────────────────────────────

func decodeBase64Simple(s string) string {
	s = strings.TrimSpace(s)
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	val := func(c byte) int {
		for i, ch := range chars {
			if byte(ch) == c {
				return i
			}
		}
		return 0
	}

	var out []byte
	for i := 0; i+3 < len(s); i += 4 {
		b0 := val(s[i])
		b1 := val(s[i+1])
		b2 := val(s[i+2])
		b3 := val(s[i+3])
		out = append(out, byte(b0<<2|b1>>4))
		if s[i+2] != '=' {
			out = append(out, byte(b1<<4|b2>>2))
		}
		if s[i+3] != '=' {
			out = append(out, byte(b2<<6|b3))
		}
	}
	return string(out)
}

// ==========SSH================
func realSSHServer() func(net.Conn) {
	return func(conn net.Conn) {
		// Just close — real SSH needs host keys and full handshake
		// For demo, use Option 1 instead
		conn.Close()
	}
}
