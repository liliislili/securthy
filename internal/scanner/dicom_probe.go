package scanner

import (
	"net"
	"time"
)

type DICOMProbe struct{}

func (d DICOMProbe) Name() string { return "dicom" }

func (d DICOMProbe) CanHandle(port int) bool {
	return port == 104 || port == 11112
}

func (d DICOMProbe) Probe(conn net.Conn) ProbeResult {
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// DICOM C-ECHO request (minimal Association Request)
	// This is the standard "ping" for DICOM servers
	cEcho := []byte{
		0x01, 0x00, // PDU type: A-ASSOCIATE-RQ
		0x00, 0x00, // reserved
		0x00, 0x00, 0x00, 0x4a, // length
		0x00, 0x01, // protocol version
		0x00, 0x00, // reserved
	}

	conn.Write(cEcho)

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		// Even a rejection confirms DICOM is running
		return ProbeResult{
			Service: "dicom",
			Banner:  "DICOM service detected (no banner)",
			Raw:     "",
		}
	}

	// PDU type 0x02 = A-ASSOCIATE-AC (accepted), 0x03 = rejected
	pduType := buf[0]
	status := "unknown response"
	if pduType == 0x02 {
		status = "DICOM association accepted - CRITICAL EXPOSURE"
	} else if pduType == 0x03 {
		status = "DICOM service present (association rejected)"
	}

	return ProbeResult{
		Service: "dicom",
		Banner:  status,
		Raw:     string(buf[:n]),
	}
}
