package scanner

import (
	"net"
	"strings"
	"time"
)

type SSHProbe struct{}

func (s SSHProbe) Name() string { return "ssh" }

func (s SSHProbe) CanHandle(port int) bool {
	return port == 22
}

func (s SSHProbe) Probe(conn net.Conn) ProbeResult {
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return ProbeResult{"ssh", "", ""}
	}

	banner := strings.TrimSpace(string(buf[:n]))

	return ProbeResult{
		Service: "ssh",
		Banner:  banner,
		Raw:     banner,
	}
}
