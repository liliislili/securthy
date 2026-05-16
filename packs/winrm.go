package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// WinRM sends a PowerShell command to a Windows machine
// Uses HTTP-based WinRM (port 5985) — no extra library needed
func RunPS(ip string, creds WinCreds, script string) (string, error) {
	// Encode script as base64 for safe transport
	encoded := base64.StdEncoding.EncodeToString(
		[]byte(string([]byte{0xff, 0xfe}) + toUTF16LE(script)),
	)
	cmd := fmt.Sprintf("powershell -EncodedCommand %s", encoded)
	return winrmExec(ip, creds, cmd)
}

func winrmExec(ip string, creds WinCreds, command string) (string, error) {
	// WinRM SOAP envelope
	envelope := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsa:To>http://%s:5985/wsman</wsa:To>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:MessageID>uuid:1</wsa:MessageID>
    <wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
  </s:Header>
  <s:Body>
    <rsp:CommandLine><rsp:Command>%s</rsp:Command></rsp:CommandLine>
  </s:Body>
</s:Envelope>`, ip, xmlEscape(command))

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		},
	}

	req, err := http.NewRequest("POST",
		fmt.Sprintf("http://%s:5985/wsman", ip),
		bytes.NewBufferString(envelope))
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(creds.User, creds.Pass)
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("WinRM connection failed to %s: %w", ip, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return "", fmt.Errorf("WinRM auth failed on %s — check credentials", ip)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("WinRM returned %d on %s", resp.StatusCode, ip)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return extractWinRMOutput(buf.String()), nil
}

func extractWinRMOutput(soap string) string {
	// Extract text between <rsp:Stream> tags
	start := strings.Index(soap, "<rsp:Stream")
	if start == -1 {
		return soap
	}
	end := strings.Index(soap[start:], "</rsp:Stream>")
	if end == -1 {
		return ""
	}
	encoded := soap[start : start+end]
	// Strip the tag
	tagEnd := strings.Index(encoded, ">")
	if tagEnd == -1 {
		return ""
	}
	encoded = encoded[tagEnd+1:]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded
	}
	return string(decoded)
}

func toUTF16LE(s string) string {
	var buf strings.Builder
	for _, r := range s {
		buf.WriteByte(byte(r))
		buf.WriteByte(0)
	}
	return buf.String()
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
