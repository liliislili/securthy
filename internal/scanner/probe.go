package scanner

import "net"

type ProbeResult struct {
	Service string
	Banner  string
	Raw     string
}

type Probe interface {
	Name() string
	CanHandle(port int) bool
	Probe(conn net.Conn) ProbeResult
}

var probes []Probe

func RegisterProbe(p Probe) {
	probes = append(probes, p)
}

func GetProbe(port int) Probe {
	for _, p := range probes {
		if p.CanHandle(port) {
			return p
		}
	}
	return nil
}
func ProbeService(port int, conn net.Conn) ProbeResult {
	p := GetProbe(port)

	if p == nil {
		raw := genericBanner(conn)
		return ProbeResult{
			Service: "unknown",
			Banner:  raw,
			Raw:     raw,
		}
	}

	return p.Probe(conn)
}
