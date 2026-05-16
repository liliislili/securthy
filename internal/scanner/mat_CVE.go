package scanner

import (
	"strings"
)

func FindCVEs(service, version string) []CVE {
	var results []CVE

	for _, cve := range CVEDB {
		// Check if service name matches (partial match)
		if !strings.Contains(strings.ToLower(service), cve.Service) {
			continue
		}

		// "any" means the exposure exists regardless of version
		if cve.VersionRule == "any" {
			results = append(results, cve)
			continue
		}

		// Version-specific rules (e.g. "<8.3")
		if strings.HasPrefix(cve.VersionRule, "<") && version != "" {
			target := strings.TrimPrefix(cve.VersionRule, "<")
			if versionLess(version, target) {
				results = append(results, cve)
			}
		}
	}

	return results
}
