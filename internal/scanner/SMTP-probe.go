package scanner

import (
	"net"
	"time"
)

type SMTPProbe struct{}

func (s SMTPProbe) Name() string { return "smtp" }

func (s SMTPProbe) CanHandle(port int) bool {
	return port == 25 || port == 587
}

func (s SMTPProbe) Probe(conn net.Conn) ProbeResult {
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 1024)

	n, _ := conn.Read(buf)
	greeting := string(buf[:n])

	conn.Write([]byte("EHLO scanner.local\r\n"))

	n, _ = conn.Read(buf)
	response := string(buf[:n])

	return ProbeResult{
		Service: "smtp",
		Banner:  greeting,
		Raw:     greeting + response,
	}
}
