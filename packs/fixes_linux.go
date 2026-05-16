package main

import "fmt"

// ── Shell scripts for Linux (DEM server) ─────────────────────────────────────

const shDisableTelnet = `
which telnetd && systemctl stop telnetd && systemctl disable telnetd || true
which inetd && update-inetd --disable telnet 2>/dev/null || true
ufw deny 23/tcp 2>/dev/null || true
echo "Telnet disabled"
`

const shEnableUFWRules = `
which ufw || apt-get install -y ufw
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow 8080/tcp
ufw deny 3306/tcp
ufw deny 5432/tcp
ufw deny 27017/tcp
ufw deny 161/udp
ufw deny 69/udp
ufw reload
echo "UFW firewall configured"
`

const shUpgradeSNMPv3 = `
which snmpd || apt-get install -y snmpd
# Stop service, reconfigure
systemctl stop snmpd

# Remove dangerous public community
sed -i '/^rocommunity public/d' /etc/snmp/snmpd.conf
sed -i '/^rwcommunity private/d' /etc/snmp/snmpd.conf

# Add SNMPv3 user (SHA auth + AES privacy)
net-snmp-config --create-snmpv3-user -ro -a SHA -A "Securthy2024!" -x AES -X "Securthy2024!" securthy_monitor

systemctl start snmpd
systemctl enable snmpd
echo "SNMPv3 configured, public community removed"
`

const shSecureFHIR = `
# Check if nginx is installed (common FHIR reverse proxy)
which nginx || apt-get install -y nginx

# Create authentication config for FHIR endpoints
cat > /etc/nginx/conf.d/fhir-auth.conf << 'NGINX'
server {
    listen 8080;

    # Require auth on all patient data endpoints
    location ~ ^/fhir/(Patient|Observation|MedicationRequest|DiagnosticReport|Condition) {
        auth_basic "DEM FHIR API";
        auth_basic_user_file /etc/nginx/.fhir-passwd;
        proxy_pass http://localhost:8090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Metadata can be public (capability statement)
    location /fhir/metadata {
        proxy_pass http://localhost:8090;
    }

    # Block everything else by default
    location / {
        return 403 '{"error":"unauthorized"}';
    }
}
NGINX

# Create htpasswd for FHIR API
which htpasswd || apt-get install -y apache2-utils
htpasswd -cb /etc/nginx/.fhir-passwd dem_api SecurthyDZ2024!

nginx -t && systemctl reload nginx
echo "FHIR API authentication enabled"
`

const shEnableTLSHL7 = `
# Install stunnel to wrap HL7/MLLP traffic in TLS
which stunnel4 || apt-get install -y stunnel4

# Generate self-signed cert for HL7 TLS (replace with CA cert in production)
mkdir -p /etc/stunnel/certs
openssl req -new -x509 -days 365 -nodes \
    -out /etc/stunnel/certs/hl7.crt \
    -keyout /etc/stunnel/certs/hl7.key \
    -subj "/C=DZ/O=Hospital/CN=HL7-Gateway"

cat > /etc/stunnel/hl7-tls.conf << 'STUNNEL'
[hl7-tls]
accept  = 2576
connect = 2575
cert    = /etc/stunnel/certs/hl7.crt
key     = /etc/stunnel/certs/hl7.key
STUNNEL

systemctl enable stunnel4
systemctl restart stunnel4
echo "HL7 TLS gateway active on port 2576 (plaintext 2575 → TLS 2576)"
`

const shEnableTLSDICOM = `
# Install stunnel for DICOM TLS wrapping
which stunnel4 || apt-get install -y stunnel4

mkdir -p /etc/stunnel/certs
openssl req -new -x509 -days 365 -nodes \
    -out /etc/stunnel/certs/dicom.crt \
    -keyout /etc/stunnel/certs/dicom.key \
    -subj "/C=DZ/O=Hospital/CN=DICOM-Gateway"

cat > /etc/stunnel/dicom-tls.conf << 'STUNNEL'
[dicom-tls]
accept  = 11112
connect = 104
cert    = /etc/stunnel/certs/dicom.crt
key     = /etc/stunnel/certs/dicom.key
STUNNEL

systemctl enable stunnel4
systemctl restart stunnel4
echo "DICOM TLS gateway active on port 11112 (104 plaintext → 11112 TLS)"
`

const shHardenSSH = `
# Harden SSH configuration
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat >> /etc/ssh/sshd_config << 'SSH'

# Securthy hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
Protocol 2
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
X11Forwarding no
SSH

systemctl restart sshd
echo "SSH hardened: root login disabled, password auth disabled"
`

const shInstallFail2ban = `
which fail2ban-server || apt-get install -y fail2ban

cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
F2B

systemctl enable fail2ban
systemctl restart fail2ban
echo "Fail2ban installed and configured"
`

// ApplyLinuxFix runs a specific shell fix on a Linux host via SSH
func ApplyLinuxFix(ip string, creds SSHCreds, fixName string, log *RunLog) {
	scripts := map[string]string{
		"disable-telnet":   shDisableTelnet,
		"ufw-firewall":     shEnableUFWRules,
		"snmpv3-upgrade":   shUpgradeSNMPv3,
		"fhir-auth":        shSecureFHIR,
		"tls-hl7":          shEnableTLSHL7,
		"tls-dicom":        shEnableTLSDICOM,
		"harden-ssh":       shHardenSSH,
		"install-fail2ban": shInstallFail2ban,
	}

	script, ok := scripts[fixName]
	if !ok {
		log.Add(ip, fixName, "linux", false, "", "unknown fix name")
		return
	}

	fmt.Printf("  Applying %-35s on %s...\n", fixName, ip)
	out, err := RunSSHScript(ip, creds, script)
	if err != nil {
		log.Add(ip, fixName, "linux", false, "", err.Error())
		return
	}

	log.Add(ip, fixName, "linux", true, out, "")
}
