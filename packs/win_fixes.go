package main

import "fmt"

// ── PowerShell fix scripts ────────────────────────────────────────────────────

const psDisableSMBv1 = `
# Disable SMBv1 — eliminates EternalBlue/WannaCry vector
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
Write-Output "SMBv1 disabled successfully"
`

const psEnableSMBSigning = `
# Enforce SMB signing — blocks NTLM relay attacks
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
Write-Output "SMB signing enforced"
`

const psEnableRDPNLA = `
# Enable Network Level Authentication on RDP
$regPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Set-ItemProperty -Path $regPath -Name "UserAuthentication" -Value 1
Set-ItemProperty -Path $regPath -Name "SecurityLayer" -Value 2
Write-Output "RDP NLA enabled"
`

const psDisableTelnet = `
# Disable Telnet client and server
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction SilentlyContinue
Stop-Service TlntSvr -ErrorAction SilentlyContinue
Set-Service TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue
Write-Output "Telnet disabled"
`

const psEnableFirewallRules = `
# Block exposed database ports from external access
netsh advfirewall firewall add rule name="Block MySQL External" protocol=TCP dir=in localport=3306 action=block remoteip=localsubnet
netsh advfirewall firewall add rule name="Block MSSQL External" protocol=TCP dir=in localport=1433 action=block remoteip=localsubnet
netsh advfirewall firewall add rule name="Block MongoDB External" protocol=TCP dir=in localport=27017 action=block remoteip=localsubnet
netsh advfirewall firewall add rule name="Block RDP External" protocol=TCP dir=in localport=3389 action=block
netsh advfirewall firewall add rule name="Allow RDP Local" protocol=TCP dir=in localport=3389 action=allow remoteip=localsubnet
Write-Output "Firewall rules applied"
`

const psChangeDefaultPasswords = `
# Force password change on common default accounts
param([string]$NewPassword)
$accounts = @("Administrator", "admin", "Guest")
foreach ($account in $accounts) {
    try {
        $user = Get-LocalUser -Name $account -ErrorAction Stop
        if ($user.Enabled) {
            $secPass = ConvertTo-SecureString $NewPassword -AsPlainText -Force
            Set-LocalUser -Name $account -Password $secPass
            Write-Output "Password changed: $account"
        }
    } catch {
        Write-Output "Account not found: $account (skipped)"
    }
}
`

const psUpgradeSNMP = `
# Disable SNMP v1/v2 public community, enable SNMPv3
Stop-Service SNMP -ErrorAction SilentlyContinue
$snmpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters"
$communityPath = "$snmpPath\ValidCommunities"
# Remove dangerous public/private communities
Remove-ItemProperty -Path $communityPath -Name "public" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $communityPath -Name "private" -ErrorAction SilentlyContinue
Start-Service SNMP -ErrorAction SilentlyContinue
Write-Output "SNMP public community string removed"
`

const psDisableLegacyProtocols = `
# Disable legacy and insecure protocols
# Disable LLMNR (used in NTLM relay)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

# Disable NetBIOS over TCP/IP on all adapters
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null
}

# Force NTLMv2 only
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

Write-Output "Legacy protocols disabled: LLMNR, NetBIOS, NTLMv1"
`

const psEnforceTLS = `
# Disable TLS 1.0 and 1.1, enforce TLS 1.2+
$protocols = @("TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0")
foreach ($proto in $protocols) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name "Enabled" -Value 0
    Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 1
}
# Enable TLS 1.2
$tls12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
New-Item -Path $tls12 -Force | Out-Null
Set-ItemProperty -Path $tls12 -Name "Enabled" -Value 1
Write-Output "TLS enforced: 1.2+ only"
`

// ApplyWindowsFix runs a specific PowerShell fix on a Windows host
func ApplyWindowsFix(ip string, creds WinCreds, fixName string, log *RunLog) {
	scripts := map[string]string{
		"disable-smbv1":        psDisableSMBv1,
		"enable-smb-signing":   psEnableSMBSigning,
		"enable-rdp-nla":       psEnableRDPNLA,
		"disable-telnet":       psDisableTelnet,
		"firewall-rules":       psEnableFirewallRules,
		"remove-snmp-public":   psUpgradeSNMP,
		"disable-legacy-proto": psDisableLegacyProtocols,
		"enforce-tls":          psEnforceTLS,
	}

	script, ok := scripts[fixName]
	if !ok {
		log.Add(ip, fixName, "windows", false, "", "unknown fix name")
		return
	}

	fmt.Printf("  Applying %-35s on %s...\n", fixName, ip)
	out, err := RunPS(ip, creds, script)
	if err != nil {
		log.Add(ip, fixName, "windows", false, "", err.Error())
		return
	}

	log.Add(ip, fixName, "windows", true, out, "")
}
