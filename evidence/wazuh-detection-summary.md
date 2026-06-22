# Wazuh Detection Evidence Summary

Date:        June 19, 2026
Lab:         lab.local
Attacker IP: 192.168.24.2 via OpenVPN tun0

## What Was Actually Confirmed in Wazuh

Not everything was verified in the dashboard during this session. The two confirmed detections below have actual evidence from OpenSearch queries run during the session. The others are marked accordingly.

### Password Spray: Confirmed

```
Timestamp:  2026-06-19T08:12 to 08:20 UTC
Rule:       60122  Logon Failure Unknown user or bad password
Level:      5
Event ID:   4625
Agent:      windows-ad-dc 192.168.90.121
Source IP:  192.168.24.2
Targets:    john.doe svc-backup svc-legacy administrator guest krbtgt
Status:     Logon Failure 0xC000006D and 0xC000006A
Count:      7 events confirmed in OpenSearch
```

### DCSync: Confirmed

```
Timestamp:  2026-06-19T08:46 UTC
Rule:       110001  Directory Service Access Possible DCSync attack
Level:      12 (mail: true)
Event ID:   4662
Agent:      windows-ad-dc 192.168.90.121
Subject:    Administrator SID ...500
Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} DS-Replication-Get-Changes
AccessMask: 0x100 Control Access
Count:      20 events confirmed in OpenSearch
```

### LSASS Access: Rule fired but not from the actual attack

```
Rule:   92900  Lsass process accessed possible credential dump
Level:  12 (mail: true)
Event:  Sysmon EID 10
Source: MsMpEng.exe (Windows Defender)
Count:  16 events before rule 92901 was deployed
Note:   These were all false positives from Defender scanning
        The actual rundll32 comsvcs.dll dump was not confirmed separately
```

### Rule 92901 Deployment: Confirmed Effective

```
Deployed at: 2026-06-19T08:58:33 UTC
Before:      16 Defender FP alerts in previous period
After:       0 alerts from rule 92900 in 30 minutes post-deployment
Verification: GET query for rule.id:92900 after timestamp returned 0 hits
```

### Kerberoasting: Event ingested, rule did not fire

```
Event ID:  4769
Count:     7 hits in OpenSearch
Rule:      92755 was not triggered
Reason:    ticketEncryptionType field name does not match between rule and actual event data
Status:    Partial. Data exists but correlation rule needs fix
```

### AS-REP Roasting: Nothing generated

```
Event ID:  4768
Count:     0 hits
Reason:    Kerberos Authentication Service audit subcategory not enabled on DC
Status:    Complete blind spot. Fix requires enabling the audit subcategory
```

### Not Checked in Dashboard This Session

The following techniques were executed but their corresponding Wazuh events were not verified during the session:

Registry Run Key (Sysmon EID 13 should have fired for HKCU Run key write)
AMSI bypass (4104 Script Block Logging if PowerShell logging was active)
Lateral movement logon events (4624 Type 3 for win-agent-02 connections)
Pass the Hash logon event (4624 NTLM Type 3 zero key length)
Golden Ticket rejection events (should have generated nothing since ticket was rejected)

## All Credentials Obtained

| Account | Credential | How |
|---|---|---|
| john.doe | Winter2024! | Password spray |
| svc-backup | password123 | Kerberoasting, required two crack attempts |
| svc-legacy | password123 | AS-REP Roasting |
| Administrator | NTLM bf27edd1b8509ea3e5a081fe7b90564d | LSASS dump on win-agent-02 |
| krbtgt | NTLM 434b1005e1d2290df9fc40aa90dab391 AES256 8b2a169c... | DCSync |
| All 9 domain accounts | See Phase 6 DCSync output | DCSync via DRSUAPI |

## What Did Not Work

Golden Ticket was attempted three times and failed every time. NTLM-based ticket, AES256-based ticket with extra Domain Admins SID, and a registry change to disable PAC validation on the DC. Windows Server 2022 rejected all three with KDC_ERR_TGT_REVOKED. This technique requires Mimikatz in memory on a domain-joined machine to work against WS2022.

PsExec and WMIExec against the agents both timed out on port 445. SMB is filtered by the host firewall. WinRM was the only remote code execution path.

Scheduled task creation was attempted twice as john.doe. Both failed with access denied. Medium Mandatory Level through a WinRM session is not sufficient for this operation.

## Domain Information

```
Domain SID: S-1-5-21-2386780907-4010950167-3005633723
DC:         windows-ad-dc.lab.local 192.168.90.121
OS:         Windows Server 2022 Build 20348
SMB:        Signing required on DC
```
