package scanner

import (
	"strconv"
	"strings"
)

func versionLess(a, b string) bool {
	pa := parseVersion(a)
	pb := parseVersion(b)

	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] < pb[i] {
			return true
		}
		if pa[i] > pb[i] {
			return false
		}
	}
	return len(pa) < len(pb)
}

func parseVersion(v string) []int {
	parts := strings.Split(v, ".")
	out := []int{}

	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}
