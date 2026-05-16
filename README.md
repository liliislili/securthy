# Securthy — Healthcare Network Security Platform

A modular security assessment platform built for Algerian hospital networks.
Scans network infrastructure and employees, scores against ISO 27001, and automatically applies fixes.

## Architecture
## Modules

### 1. Network Scanner
- TCP/UDP port scanning with healthcare-specific ports
- Protocol probes: DICOM, HL7, FHIR, SSH, SMB, RDP, SNMP, Telnet, FTP
- Vulnerability checks: CVE matching, TLS audit, default credentials, VLAN segmentation
- ISO 27001 scoring: A.9, A.10, A.12, A.13, A.14

### 2. Employee Scanner  
- Phishing risk: SPF/DKIM/DMARC check, open relay detection
- Password audit: weak credential testing on FTP/HTTP
- WiFi scan: WEP/open network detection
- Session, privilege, USB, browser, data leakage risk
- ISO 27001 human controls: A.6.3.1, A.5.17, A.8.20, A.8.23

### 3. Remediation Packs (3 tiers)
- **Pack Essentiel** — quick wins: disable SMBv1, enable RDP NLA, change default passwords
- **Pack Sécurité** — architecture: VLAN setup, TLS on DICOM/HL7, FHIR auth
- **Pack Conformité** — full compliance: ministry report, staff training, quarterly scans

### 4. Hospital Simulator
- 12 simulated devices with real protocol handlers
- Deliberate vulnerabilities for demo purposes
- Auto-generates employee list

## Usage

```bash
# Build
go build -o scanner_bin ./cmd/
go build -o employee_bin ./employee/
go build -o employee_packs_bin ./employee_packs/
go build -o packs_bin ./packs/

# Start simulator (Terminal 1)
sudo /usr/local/go/bin/go run ./simulator

# Network scan (Terminal 2)
./scanner_bin 127.0.0.0/24

# Employee scan
./employee_bin employees.json

# Apply network fixes
./packs_bin --targets=targets.json --ssh-key=~/.ssh/id_rsa

# Generate employee remediation plan
./employee_packs_bin employee_report_*.json
```

## Requirements
- Go 1.22+
- Linux (Ubuntu/Kali/Debian)
- sudo (for simulator loopback aliases)
- SSH key pair (~/.ssh/id_rsa)

## ISO 27001 Coverage
Network: A.9 (Access) · A.10 (Crypto) · A.12 (Operations) · A.13 (Network) · A.14 (Acquisition)  
Human:   A.6.3.1 (Awareness) · A.5.17 (Auth) · A.8.20 (WiFi) · A.8.23 (Email) · A.5.18 (Privilege)

---
Built for CHU/hospital networks in Algeria — DEM/FHIR/DICOM/HL7 aware.
# securthy
# securthy
# securthy
# securthy
# securthy
