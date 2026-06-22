# enable-audit-policy.ps1
# Enables all audit policies required for complete Wazuh detection coverage
# Run as Administrator on the Domain Controller and on each agent

Write-Host "[*] Enabling audit policies for Wazuh detection coverage..." -ForegroundColor Cyan

# Logon and logoff events
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable

# Kerberos events (required for Kerberoasting and AS-REP Roasting detection)
# Without these, event 4768 and 4769 are not generated
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Directory Service Access (required for DCSync and BloodHound detection)
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable

# Process creation (required for Sysmon supplement and legacy process tracking)
auditpol /set /subcategory:"Process Creation" /success:enable

# Object access
auditpol /set /subcategory:"Other Object Access Events" /success:enable
auditpol /set /subcategory:"Registry" /success:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

# Account management events
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable

# Policy changes
auditpol /set /subcategory:"Audit Policy Change" /success:enable

# Privilege use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

Write-Host "[+] Audit policies configured" -ForegroundColor Green

# Enable PowerShell Script Block Logging (required for detecting AMSI bypass and encoded commands)
Write-Host "`n[*] Enabling PowerShell Script Block Logging..." -ForegroundColor Cyan

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v "EnableModuleLogging" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f

Write-Host "[+] PowerShell Script Block Logging enabled" -ForegroundColor Green
Write-Host "[!] Run this script on all domain-joined machines for complete detection coverage" -ForegroundColor Yellow
