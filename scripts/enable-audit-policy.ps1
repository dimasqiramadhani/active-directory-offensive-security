# enable-audit-policy.ps1  (v2)
# Enables the audit policies required for COMPLETE Wazuh detection coverage of the
# AD red-team kill chain documented in this lab. Run as Administrator on the Domain
# Controller and on each member host. v2 adds the subcategories that the new detection
# rules (92761-92767) depend on, plus channel-forwarding guidance.
#
# WHY each block exists is annotated so the audit surface can be defended in review.

Write-Host "[*] Enabling audit policies for Wazuh detection coverage..." -ForegroundColor Cyan

# --- Logon / logoff (4624/4625/4634) : password spray 92751, PtH 92758 ---
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# --- Kerberos (4768/4769) : Kerberoasting 92755, AS-REP 92756, forged-ticket 92763 ---
# Without these, 4768/4769 are never generated. This is the single most common reason
# Kerberos detections silently fail (the AS-REP blind spot in this lab).
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# --- Directory Service (4662) : BloodHound recon 92750, DCSync 92760 ---
# 4662 only carries the replication GUID when DS Access auditing is on AND a SACL
# exists on the domain naming context. Enabling the subcategory is necessary but not
# always sufficient; on a fresh DC the default SACL already audits Replicating
# Directory Changes for Everyone. Verify with: Get-Acl "AD:\$((Get-ADDomain).DistinguishedName)" | Select -Expand Audit
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable

# --- Account / group / policy management ---
# 4738 UAC change : AS-REP target creation 92765
# 4728/4732/4756  : privileged group change 92766
# 4739            : domain policy weakened 92764
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

# --- Process / object / privilege ---
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
auditpol /set /subcategory:"Registry" /success:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

Write-Host "[+] Audit subcategories configured" -ForegroundColor Green

# --- PowerShell logging (4104) : suspicious PS 92752, AMSI bypass 92762 ---
Write-Host "`n[*] Enabling PowerShell Script Block + Module logging..." -ForegroundColor Cyan
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v "EnableModuleLogging" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f
Write-Host "[+] PowerShell logging enabled" -ForegroundColor Green

# --- Channel forwarding reminder for the Wazuh agent ---
# The new Defender-tamper rule 92761 reads the Microsoft-Windows-Windows Defender/Operational
# channel (events 5001/5010/5012/5101). That channel is NOT collected by default. Add it to
# the agent ossec.conf on each host, then restart the agent:
#
#   <localfile>
#     <location>Microsoft-Windows-Windows Defender/Operational</location>
#     <log_format>eventchannel</log_format>
#   </localfile>
#
# 92767 (registry route) and 92754 (Run key) depend on Sysmon EID 12/13 being enabled in the
# Sysmon config (Olaf Hartong's config covers RegistryEvent by default).
Write-Host "`n[!] Add the Defender Operational channel to each agent's ossec.conf (see comment block)." -ForegroundColor Yellow
Write-Host "[!] Run this script on the DC AND every member host for full coverage." -ForegroundColor Yellow

# --- Verification ---
Write-Host "`n[+] Verifying key subcategories..." -ForegroundColor Green
auditpol /get /subcategory:"Kerberos Authentication Service","Directory Service Access","User Account Management"
