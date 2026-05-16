package identity

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type PasswordAuditResult struct {
	Service       string
	IP            string
	Port          int
	WeakPassFound bool
	Password      string
	Username      string
	Findings      []string
}

var weakPasswords = []string{
	"", "admin", "password", "123456", "1234", "12345678",
	"admin123", "root", "toor", "pass", "test", "guest",
	"azerty", "azerty123", "motdepasse", "hopital", "hospital",
	"sante", "medecin", "docteur", "infirmier",
	"dz123", "algerie", "constantine", "alger", "oran",
	"admin@123", "Admin1234", "P@ssw0rd", "Passw0rd",
	"changeme", "default", "setup", "install",
	"2020", "2021", "2022", "2023", "2024",
	"admin2024", "hopital2024", "sante2024",
}

// Run is the main entry point called by engine.go
func Run(ip string) float64 {
	results := AuditPasswords(ip, []string{"ftp", "http"})

	risk := 20.0
	for _, r := range results {
		if r.WeakPassFound {
			risk += 40.0
		}
		if len(r.Findings) > 0 {
			risk += 10.0
		}
	}

	if risk > 100 {
		return 100
	}
	return risk
}

func AuditPasswords(ip string, services []string) []PasswordAuditResult {
	var results []PasswordAuditResult

	for _, service := range services {
		switch service {
		case "ssh":
			result := auditSSHPasswords(ip)
			if result != nil {
				results = append(results, *result)
			}
		case "ftp":
			result := auditFTPPasswords(ip)
			if result != nil {
				results = append(results, *result)
			}
		case "http":
			result := auditHTTPPasswords(ip, 80)
			if result != nil {
				results = append(results, *result)
			}
		}
	}

	return results
}

func auditSSHPasswords(ip string) *PasswordAuditResult {
	result := &PasswordAuditResult{
		Service: "ssh",
		IP:      ip,
		Port:    22,
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	buf := make([]byte, 256)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	banner := string(buf[:n])

	if strings.Contains(banner, "SSH") {
		result.Findings = append(result.Findings,
			fmt.Sprintf("INFO: SSH service on %s — verify password auth is disabled, use keys only", ip))
	}

	return result
}

func auditFTPPasswords(ip string) *PasswordAuditResult {
	result := &PasswordAuditResult{
		Service: "ftp",
		IP:      ip,
		Port:    21,
	}

	users := []string{"admin", "ftp", "anonymous", "root"}

	for _, pass := range weakPasswords[:10] {
		for _, u := range users {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:21", ip), 2*time.Second)
			if err != nil {
				return nil
			}

			buf := make([]byte, 512)
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Read(buf)

			fmt.Fprintf(conn, "USER %s\r\n", u)
			conn.Read(buf)
			fmt.Fprintf(conn, "PASS %s\r\n", pass)
			n, _ := conn.Read(buf)
			conn.Close()

			response := string(buf[:n])
			if strings.Contains(response, "230") {
				result.WeakPassFound = true
				result.Username = u
				result.Password = pass
				result.Findings = append(result.Findings,
					fmt.Sprintf("CRITICAL: FTP on %s accepts weak credentials — user:'%s' pass:'%s'", ip, u, pass))
				return result
			}
		}
	}

	return result
}

func auditHTTPPasswords(ip string, port int) *PasswordAuditResult {
	result := &PasswordAuditResult{
		Service: "http",
		IP:      ip,
		Port:    port,
	}

	adminPaths := []string{"/admin", "/login", "/manager", "/admin/login"}
	users := []string{"admin", "administrator", "root"}

	for _, user := range users {
		for _, pass := range weakPasswords[:15] {
			for _, path := range adminPaths {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
				if err != nil {
					return nil
				}

				authHeader := basicAuthEncode(user, pass)
				req := fmt.Sprintf(
					"GET %s HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\n\r\n",
					path, ip, authHeader)

				conn.SetDeadline(time.Now().Add(2 * time.Second))
				conn.Write([]byte(req))
				buf := make([]byte, 512)
				n, _ := conn.Read(buf)
				conn.Close()

				resp := string(buf[:n])
				if strings.Contains(resp, "200 OK") &&
					!strings.Contains(strings.ToLower(resp), "unauthorized") {
					result.WeakPassFound = true
					result.Username = user
					result.Password = pass
					result.Findings = append(result.Findings,
						fmt.Sprintf("CRITICAL: HTTP admin on %s:%d accepts weak credentials user:'%s' pass:'%s' at %s",
							ip, port, user, pass, path))
					return result
				}
			}
		}
	}

	return result
}

func basicAuthEncode(user, pass string) string {
	s := user + ":" + pass
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	src := []byte(s)
	dst := make([]byte, 4*((len(src)+2)/3))
	j := 0
	for i := 0; i < len(src); i += 3 {
		b0 := src[i]
		b1 := byte(0)
		b2 := byte(0)
		if i+1 < len(src) {
			b1 = src[i+1]
		}
		if i+2 < len(src) {
			b2 = src[i+2]
		}
		dst[j] = chars[b0>>2]
		dst[j+1] = chars[(b0&3)<<4|b1>>4]
		if i+1 < len(src) {
			dst[j+2] = chars[(b1&0xf)<<2|b2>>6]
		} else {
			dst[j+2] = '='
		}
		if i+2 < len(src) {
			dst[j+3] = chars[b2&0x3f]
		} else {
			dst[j+3] = '='
		}
		j += 4
	}
	return string(dst[:j])
}