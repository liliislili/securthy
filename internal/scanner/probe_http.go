package scanner

import (
	"net"
	"time"
)

type HTTPProbe struct{}

func (h HTTPProbe) Name() string { return "http" }

func (h HTTPProbe) CanHandle(port int) bool {
	return port == 80 || port == 8080 || port == 8000
}

func (h HTTPProbe) Probe(conn net.Conn) ProbeResult {
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	req := "GET / HTTP/1.0\r\nHost: scan\r\n\r\n"
	conn.Write([]byte(req))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return ProbeResult{"http", "", ""}
	}

	raw := string(buf[:n])
	server := extractHeader(raw, "Server")

	return ProbeResult{
		Service: "http",
		Banner:  server,
		Raw:     raw,
	}
}
