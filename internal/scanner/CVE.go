package scanner

type CVE struct {
	ID          string
	Service     string
	VersionRule string
	Severity    int
	Description string
}

var CVEDB = []CVE{

	// ========== DICOM (medical imaging) ==========
	{
		ID:          "CVE-2020-7505",
		Service:     "dicom",
		VersionRule: "any",
		Severity:    9,
		Description: "Unauthenticated DICOM server exposes patient imaging data (HIPAA/RGPD violation)",
	},
	{
		ID:          "CVE-2019-11687",
		Service:     "dicom",
		VersionRule: "any",
		Severity:    8,
		Description: "DICOM file parsing vulnerability allows remote code execution via malformed images",
	},

	// ========== HL7 (health data exchange) ==========
	{
		ID:          "CVE-2021-0001",
		Service:     "hl7",
		VersionRule: "any",
		Severity:    9,
		Description: "Unauthenticated HL7 MLLP listener exposes patient demographic and medical records",
	},
	{
		ID:          "CVE-2019-16889",
		Service:     "hl7",
		VersionRule: "any",
		Severity:    7,
		Description: "HL7 message injection allows unauthorized patient record modification",
	},

	// ========== SSH ==========
	{
		ID:          "CVE-2020-14145",
		Service:     "openssh",
		VersionRule: "<8.3",
		Severity:    6,
		Description: "OpenSSH user enumeration via timing attack",
	},
	{
		ID:          "CVE-2016-0777",
		Service:     "openssh",
		VersionRule: "<7.1",
		Severity:    8,
		Description: "OpenSSH roaming feature leaks private keys to malicious server",
	},
	{
		ID:          "CVE-2023-38408",
		Service:     "openssh",
		VersionRule: "<9.3",
		Severity:    9,
		Description: "Remote code execution in OpenSSH agent forwarding (regreSSHion)",
	},

	// ========== Nginx ==========
	{
		ID:          "CVE-2021-23017",
		Service:     "nginx",
		VersionRule: "<1.20.0",
		Severity:    7,
		Description: "Nginx DNS resolver buffer overflow",
	},
	{
		ID:          "CVE-2019-20372",
		Service:     "nginx",
		VersionRule: "<1.17.7",
		Severity:    8,
		Description: "Nginx HTTP/2 request smuggling vulnerability",
	},

	// ========== Apache ==========
	{
		ID:          "CVE-2021-41773",
		Service:     "apache",
		VersionRule: "<2.4.50",
		Severity:    10,
		Description: "Apache path traversal and RCE (actively exploited in the wild)",
	},
	{
		ID:          "CVE-2021-42013",
		Service:     "apache",
		VersionRule: "<2.4.51",
		Severity:    10,
		Description: "Apache path traversal bypass (follow-up to CVE-2021-41773)",
	},

	// ========== Telnet (critical in hospitals) ==========
	{
		ID:          "EXPOSURE-TELNET-001",
		Service:     "telnet",
		VersionRule: "any",
		Severity:    10,
		Description: "Telnet transmits credentials in plaintext - CRITICAL on medical networks",
	},

	// ========== FTP ==========
	{
		ID:          "EXPOSURE-FTP-001",
		Service:     "ftp",
		VersionRule: "any",
		Severity:    8,
		Description: "FTP transmits credentials and data in plaintext",
	},
	{
		ID:          "CVE-2015-3306",
		Service:     "ftp",
		VersionRule: "any",
		Severity:    10,
		Description: "ProFTPd mod_copy allows unauthenticated file copy/read on server",
	},

	// ========== SMB (ransomware vector) ==========
	{
		ID:          "CVE-2017-0144",
		Service:     "smb",
		VersionRule: "any",
		Severity:    10,
		Description: "EternalBlue - SMB RCE used by WannaCry ransomware (hospitals targeted)",
	},
	{
		ID:          "CVE-2020-0796",
		Service:     "smb",
		VersionRule: "any",
		Severity:    10,
		Description: "SMBGhost - SMBv3 RCE without authentication",
	},

	// ========== RDP ==========
	{
		ID:          "CVE-2019-0708",
		Service:     "rdp",
		VersionRule: "any",
		Severity:    10,
		Description: "BlueKeep - RDP pre-auth RCE, wormable, widely exploited",
	},
	{
		ID:          "CVE-2019-1182",
		Service:     "rdp",
		VersionRule: "any",
		Severity:    10,
		Description: "DejaBlue - RDP pre-auth RCE on Windows 10 and Server 2019",
	},

	// ========== Databases (exposed DB = disaster in healthcare) ==========
	{
		ID:          "EXPOSURE-MYSQL-001",
		Service:     "mysql",
		VersionRule: "any",
		Severity:    9,
		Description: "MySQL port exposed externally - patient database directly reachable",
	},
	{
		ID:          "EXPOSURE-MONGODB-001",
		Service:     "mongodb",
		VersionRule: "any",
		Severity:    10,
		Description: "MongoDB exposed without auth - historically mass-exploited for ransom",
	},
	{
		ID:          "EXPOSURE-MSSQL-001",
		Service:     "mssql",
		VersionRule: "any",
		Severity:    9,
		Description: "MSSQL port exposed - common target in hospital ransomware attacks",
	},

	// ========== SNMP ==========
	{
		ID:          "CVE-2017-6736",
		Service:     "snmp",
		VersionRule: "any",
		Severity:    8,
		Description: "SNMP v1/v2 uses community string 'public' by default - full device info leak",
	},

	// ========== Modbus (medical IoT) ==========
	{
		ID:          "EXPOSURE-MODBUS-001",
		Service:     "modbus",
		VersionRule: "any",
		Severity:    9,
		Description: "Modbus has no authentication - direct control of connected medical devices",
	},
}
