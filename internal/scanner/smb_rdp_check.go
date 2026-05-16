package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// ── SMB ──────────────────────────────────────────────────────────────────────

type SMBResult struct {
	Open            bool
	SigningEnabled  bool
	SigningRequired bool   // if false + enabled = optional = still vulnerable
	Version         string // SMBv1, SMBv2, SMBv3
	SMBv1           bool   // SMBv1 = EternalBlue-class risk
	Vulnerable      bool   // true if signing not required
}

// CheckSMB sends an SMB negotiate request and reads signing + version info
func CheckSMB(ip string) SMBResult {
	result := SMBResult{}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), 3*time.Second)
	if err != nil {
		return result
	}
	defer conn.Close()
	result.Open = true
	conn.SetDeadline(time.Now().Add(4 * time.Second))

	// SMBv2 Negotiate Request — asks server to list its supported dialects
	// and reveals its signing policy in the response flags
	negotiateRequest := []byte{
		// NetBIOS session header (4 bytes)
		0x00, 0x00, 0x00, 0x54,
		// SMB2 header
		0xfe, 0x53, 0x4d, 0x42, // ProtocolId: \xfeSMB
		0x40, 0x00, // StructureSize: 64
		0x00, 0x00, // CreditCharge
		0x00, 0x00, 0x00, 0x00, // Status
		0x00, 0x00, // Command: Negotiate (0)
		0x1f, 0x00, // CreditRequest
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // NextCommand
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // TreeId
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// SMB2 Negotiate body
		0x24, 0x00, // StructureSize: 36
		0x02, 0x00, // DialectCount: 2
		0x01, 0x00, // SecurityMode: signing enabled (but not required)
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid
		0x00, 0x00, 0x00, 0x00, // ClientStartTime
		0x02, 0x02, // Dialect: SMB 2.0.2
		0x10, 0x02, // Dialect: SMB 2.1.0
	}

	_, err = conn.Write(negotiateRequest)
	if err != nil {
		return result
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 72 {
		// Try SMBv1 fallback
		return checkSMBv1(ip, result)
	}

	// Parse SMB2 Negotiate Response
	// Skip NetBIOS header (4 bytes) + SMB2 header (64 bytes) = offset 68
	if n > 72 && buf[4] == 0xfe && buf[5] == 'S' {
		result.Version = "SMBv2/v3"

		// SecurityMode is at offset 68+2 = 70 in the response
		// Bit 0 = SMB2_NEGOTIATE_SIGNING_ENABLED
		// Bit 1 = SMB2_NEGOTIATE_SIGNING_REQUIRED
		if n > 71 {
			secMode := buf[70]
			result.SigningEnabled = secMode&0x01 != 0
			result.SigningRequired = secMode&0x02 != 0
		}

		// Dialect is at offset 68+4 = 72
		if n > 74 {
			dialect := binary.LittleEndian.Uint16(buf[72:74])
			switch dialect {
			case 0x0300:
				result.Version = "SMBv3.0"
			case 0x0302:
				result.Version = "SMBv3.0.2"
			case 0x0311:
				result.Version = "SMBv3.1.1"
			case 0x0210:
				result.Version = "SMBv2.1"
			case 0x0202:
				result.Version = "SMBv2.0"
			}
		}

		// Vulnerable if signing is not REQUIRED (even if enabled)
		result.Vulnerable = !result.SigningRequired
	}

	return result
}

// checkSMBv1 sends an SMBv1 negotiate and detects the ancient protocol
func checkSMBv1(ip string, base SMBResult) SMBResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), 2*time.Second)
	if err != nil {
		return base
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// SMBv1 Negotiate Protocol Request
	smbv1Neg := []byte{
		0x00, 0x00, 0x00, 0x2f, // NetBIOS length
		0xff, 0x53, 0x4d, 0x42, // SMBv1 magic
		0x72,                   // Command: Negotiate
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x01, 0x28, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sig
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, // Tree ID
		0xff, 0xff, // PID
		0x00, 0x00, // UID
		0x00, 0x00, // MID
		// Dialects
		0x00,       // WordCount
		0x0f, 0x00, // ByteCount
		0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
	}

	conn.Write(smbv1Neg)
	buf := make([]byte, 128)
	n, err := conn.Read(buf)

	if err == nil && n > 8 && buf[4] == 0xff && buf[5] == 'S' {
		base.Open = true
		base.SMBv1 = true
		base.Version = "SMBv1 (CRITICAL — EternalBlue)"
		base.Vulnerable = true
		base.SigningRequired = false
	}

	return base
}

// SMBFindings returns risk findings from SMB check
func SMBFindings(r SMBResult, ip string) []string {
	var findings []string
	if !r.Open {
		return findings
	}

	if r.SMBv1 {
		findings = append(findings,
			fmt.Sprintf("CRITICAL: SMBv1 detected on %s — vulnerable to EternalBlue/WannaCry ransomware", ip))
	}

	if r.Open && !r.SigningRequired && !r.SMBv1 {
		findings = append(findings,
			fmt.Sprintf("HIGH: SMB signing NOT required on %s (%s) — vulnerable to NTLM relay attacks", ip, r.Version))
	}

	if r.SigningEnabled && !r.SigningRequired {
		findings = append(findings,
			fmt.Sprintf("MEDIUM: SMB signing enabled but optional on %s — enforce 'RequireSecuritySignature'", ip))
	}

	return findings
}

// ── RDP ──────────────────────────────────────────────────────────────────────

type RDPResult struct {
	Open       bool
	NLAEnabled bool // Network Level Authentication
	Vulnerable bool // true if NLA is off
	Version    string
}

// CheckRDP sends an RDP connection initiation and checks for NLA enforcement
func CheckRDP(ip string) RDPResult {
	result := RDPResult{}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:3389", ip), 3*time.Second)
	if err != nil {
		return result
	}
	defer conn.Close()
	result.Open = true
	conn.SetDeadline(time.Now().Add(4 * time.Second))

	// TPKT + X.224 Connection Request with CredSSP/NLA negotiation
	// This is the standard RDP pre-auth packet
	rdpNegRequest := []byte{
		// TPKT Header
		0x03, 0x00, 0x00, 0x13,
		// X.224 Connection Request
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
		// RDP Negotiation Request — requesting PROTOCOL_SSL | PROTOCOL_HYBRID (NLA)
		0x01,       // Type: RDP_NEG_REQ
		0x00,       // Flags
		0x08, 0x00, // Length: 8
		0x03, 0x00, 0x00, 0x00, // Protocols: PROTOCOL_SSL(1) | PROTOCOL_HYBRID(2) = 3
	}

	_, err = conn.Write(rdpNegRequest)
	if err != nil {
		return result
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n < 11 {
		return result
	}

	// Parse X.224 Connection Confirm (0xd0)
	if buf[5] == 0xd0 {
		// RDP Negotiation Response starts at offset 11
		if n >= 15 {
			respType := buf[11]
			if respType == 0x02 { // TYPE_RDP_NEG_RSP
				selectedProtocol := binary.LittleEndian.Uint32(buf[15:19])
				// Protocol flags:
				// 0 = Standard RDP (no NLA, no SSL) — critical
				// 1 = SSL only
				// 2 = CredSSP/NLA
				// 3 = CredSSP + SSL
				switch selectedProtocol {
				case 0:
					result.NLAEnabled = false
					result.Version = "RDP standard (no NLA, no SSL)"
					result.Vulnerable = true
				case 1:
					result.NLAEnabled = false
					result.Version = "RDP with SSL only (no NLA)"
					result.Vulnerable = true
				case 2, 3:
					result.NLAEnabled = true
					result.Version = "RDP with NLA (CredSSP)"
					result.Vulnerable = false
				}
			} else if respType == 0x03 { // TYPE_RDP_NEG_FAILURE
				// Server rejected — still open but couldn't negotiate
				result.Vulnerable = true
				result.Version = "RDP (negotiation failed)"
			}
		}
	}

	return result
}

// RDPFindings returns risk findings from RDP check
func RDPFindings(r RDPResult, ip string) []string {
	var findings []string
	if !r.Open {
		return findings
	}

	if r.Vulnerable && r.Version == "RDP standard (no NLA, no SSL)" {
		findings = append(findings,
			fmt.Sprintf("CRITICAL: RDP on %s has NO NLA and NO SSL — credentials sent in plaintext, BlueKeep-class exposure", ip))
	} else if r.Vulnerable {
		findings = append(findings,
			fmt.Sprintf("HIGH: RDP on %s has no NLA enforcement (%s) — pre-auth attacks possible (BlueKeep, DejaBlue)", ip, r.Version))
	}

	if !r.Vulnerable {
		findings = append(findings,
			fmt.Sprintf("OK: RDP on %s enforces NLA (%s)", ip, r.Version))
	}

	return findings
}
