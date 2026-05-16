package scanner

type ScanReport struct {
	IP      string
	Port    int
	Service string
	Banner  string
	Version string
	Risk    RiskReport
}

func BuildReport(ip string, port int, service, banner string) ScanReport {
	version := ExtractVersion(banner)
	risk := CalculateRisk(service, version)

	return ScanReport{
		IP:      ip,
		Port:    port,
		Service: service,
		Banner:  banner,
		Version: version,
		Risk:    risk,
	}
}
