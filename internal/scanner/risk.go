package scanner

type RiskLevel string

const (
	LOW      RiskLevel = "LOW"
	MEDIUM   RiskLevel = "MEDIUM"
	HIGH     RiskLevel = "HIGH"
	CRITICAL RiskLevel = "CRITICAL"
)

type RiskReport struct {
	Service string
	Version string
	Score   int
	Level   RiskLevel
	CVEs    []CVE
}

func CalculateRisk(service, version string) RiskReport {
	cves := FindCVEs(service, version)

	score := 0
	for _, c := range cves {
		score += c.Severity
	}

	return RiskReport{
		Service: service,
		Version: version,
		Score:   score,
		Level:   classify(score),
		CVEs:    cves,
	}
}

func classify(score int) RiskLevel {
	switch {
	case score >= 15:
		return CRITICAL
	case score >= 8:
		return HIGH
	case score >= 3:
		return MEDIUM
	default:
		return LOW
	}
}
