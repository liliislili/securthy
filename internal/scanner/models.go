package scanner

type PortResult struct {
	Port int  `json:"port"`
	Open bool `json:"open"`
}

type HostResult struct {
	IP    string       `json:"ip"`
	Ports []PortResult `json:"ports"`
}

type ScanResult struct {
	Hosts []HostResult `json:"hosts"`
}
type ServiceInfo struct {
	IP      string
	Port    int
	Service string
	Banner  string
	Version string
	Risk    string
}
