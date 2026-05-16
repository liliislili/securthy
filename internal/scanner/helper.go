package scanner

import (
	"net"
	"strings"
	"time"
)

//
// -------------------------
// GENERIC BANNER GRABBER
// -------------------------
//

func genericBanner(conn net.Conn) string {
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(buf[:n]))
}

//
// -------------------------
// HTTP HEADER PARSER
// -------------------------
//

func extractHeader(response, header string) string {
	lines := strings.Split(response, "\r\n")

	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(header)+":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}
