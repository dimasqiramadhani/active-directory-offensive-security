# setup-ad-objects.ps1
# Creates vulnerable Active Directory objects for the red team detection lab
# Run as Administrator on the Domain Controller

Write-Host "[*] Setting up vulnerable AD objects for lab.local" -ForegroundColor Cyan

# Create john.doe as a regular domain user for initial foothold
Write-Host "[*] Creating john.doe (regular domain user)..." -ForegroundColor Yellow
New-ADUser -Name "John Doe" `
  -SamAccountName "john.doe" `
  -UserPrincipalName "john.doe@lab.local" `
  -AccountPassword (ConvertTo-SecureString "Winter2024!" -AsPlainText -Force) `
  -Enabled $true `
  -PasswordNeverExpires $true

# Create svc-backup as a Kerberoastable service account
Write-Host "[*] Creating svc-backup (Kerberoastable)..." -ForegroundColor Yellow
New-ADUser -Name "svc-backup" `
  -SamAccountName "svc-backup" `
  -AccountPassword (ConvertTo-SecureString "password123" -AsPlainText -Force) `
  -Enabled $true `
  -PasswordNeverExpires $true

# Set the SPN that makes svc-backup Kerberoastable
Set-ADUser -Identity "svc-backup" `
  -ServicePrincipalNames @{Add="HTTP/backup.lab.local"}

# Create svc-legacy as an AS-REP Roastable service account
Write-Host "[*] Creating svc-legacy (AS-REP Roastable)..." -ForegroundColor Yellow
New-ADUser -Name "svc-legacy" `
  -SamAccountName "svc-legacy" `
  -AccountPassword (ConvertTo-SecureString "password123" -AsPlainText -Force) `
  -Enabled $true `
  -PasswordNeverExpires $true

# Disable pre-authentication requirement to enable AS-REP Roasting
# Note: use Set-ADAccountControl, not Set-ADUserControl which does not exist
Set-ADAccountControl -Identity "svc-legacy" -DoesNotRequirePreAuth $true

# Add john.doe to Remote Management Users domain group for WinRM access
Write-Host "[*] Adding john.doe to Remote Management Users..." -ForegroundColor Yellow
Add-ADGroupMember -Identity "Remote Management Users" -Members "john.doe"

# Disable password complexity to allow simple test passwords
# This is required because password123 fails default complexity policy
Write-Host "[*] Relaxing password complexity policy for lab use..." -ForegroundColor Yellow
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -replace "PasswordComplexity = 1","PasswordComplexity = 0" | Set-Content C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY
net accounts /minpwlen:1

# Push john.doe as local admin on both agents
Write-Host "[*] Adding john.doe as local admin on win-agent-01..." -ForegroundColor Yellow
Invoke-Command -ComputerName win-agent-01 -ScriptBlock {
  net localgroup administrators "lab\john.doe" /add
  net localgroup "Remote Management Users" "lab\john.doe" /add
  Restart-Service WinRM
}

Write-Host "[*] Adding john.doe as local admin on win-agent-02..." -ForegroundColor Yellow
Invoke-Command -ComputerName win-agent-02 -ScriptBlock {
  net localgroup administrators "lab\john.doe" /add
  net localgroup "Remote Management Users" "lab\john.doe" /add
  Restart-Service WinRM
}

# Verify results
Write-Host "`n[+] Verification" -ForegroundColor Green
Get-ADUser -Filter * | Select-Object SamAccountName, Enabled | Format-Table

Write-Host "`n[+] SPN on svc-backup (Kerberoastable)" -ForegroundColor Green
Get-ADUser svc-backup -Properties ServicePrincipalNames | Select-Object -ExpandProperty ServicePrincipalNames

Write-Host "`n[+] PreAuth flag on svc-legacy (AS-REP Roastable)" -ForegroundColor Green
Get-ADUser svc-legacy -Properties DoesNotRequirePreAuth | Select-Object SamAccountName, DoesNotRequirePreAuth

Write-Host "`n[+] Setup complete" -ForegroundColor Green
