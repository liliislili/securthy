package scanner

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

type CredResult struct {
	Vulnerable bool
	Username   string
	Password   string
	Service    string
}

var defaultCreds = map[string][][2]string{
	"ftp": {
		{"admin", "admin"}, {"admin", "password"}, {"admin", ""},
		{"anonymous", ""}, {"ftp", "ftp"}, {"root", "root"}, {"root", ""},
	},
	"http": {
		{"admin", "admin"}, {"admin", "password"}, {"admin", "1234"},
		{"administrator", "administrator"}, {"root", "root"},
		{"service", "service"}, {"admin", "Siemens.1"},
		{"admin", "philips"}, {"admin", "admin123"},
	},
}

func CheckDefaultFTP(ip string, port int) *CredResult {
	for _, cred := range defaultCreds["ftp"] {
		user, pass := cred[0], cred[1]
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return nil
		}
		buf := make([]byte, 512)
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Read(buf)
		conn.Write([]byte(fmt.Sprintf("USER %s\r\n", user)))
		conn.Read(buf)
		conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", pass)))
		n, _ := conn.Read(buf)
		conn.Close()
		if strings.Contains(string(buf[:n]), "230") {
			return &CredResult{true, user, pass, "ftp"}
		}
	}
	return nil
}

func CheckDefaultHTTP(ip string, port int) *CredResult {
	paths := []string{"/admin", "/login", "/manager", "/admin/login"}
	for _, cred := range defaultCreds["http"] {
		user, pass := cred[0], cred[1]
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		for _, path := range paths {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
			if err != nil {
				break
			}
			req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\n\r\n", path, ip, auth)
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.Write([]byte(req))
			buf := make([]byte, 512)
			n, _ := conn.Read(buf)
			conn.Close()
			resp := string(buf[:n])
			if strings.Contains(resp, "200 OK") && !strings.Contains(strings.ToLower(resp), "unauthorized") {
				return &CredResult{true, user, pass, "http" + path}
			}
		}
	}
	return nil
}
