package scanner

import (
	"net"
	"strings"
	"time"
)

type HL7Probe struct{}

func (h HL7Probe) Name() string { return "hl7" }

func (h HL7Probe) CanHandle(port int) bool {
	return port == 2575 || port == 2576
}

func (h HL7Probe) Probe(conn net.Conn) ProbeResult {
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// HL7 MLLP (Minimal Lower Layer Protocol) ping
	// Sends a minimal HL7 v2 MSH segment wrapped in MLLP framing
	mllpStart := byte(0x0B)
	mllpEnd := []byte{0x1C, 0x0D}

	hl7Ping := "MSH|^~\\&|SCANNER|SCANNER|SERVER|SERVER|20240101||ADT^A01|1|P|2.3"
	msg := append([]byte{mllpStart}, []byte(hl7Ping)...)
	msg = append(msg, mllpEnd...)

	conn.Write(msg)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return ProbeResult{
			Service: "hl7",
			Banner:  "HL7/MLLP port open (no response to probe)",
			Raw:     "",
		}
	}

	raw := string(buf[:n])
	banner := "HL7 service detected"

	// Try to extract MSH fields for version/vendor info
	if strings.Contains(raw, "MSH") {
		fields := strings.Split(raw, "|")
		if len(fields) > 3 {
			banner = "HL7 v2 - sending app: " + fields[3]
		}
	}

	return ProbeResult{
		Service: "hl7",
		Banner:  banner,
		Raw:     raw,
	}
}
