# Phase 1: Reconnaissance

MITRE ATT&CK: T1046 T1087.002 T1069.002

## 1.1 Nmap Service Scan

```bash
nmap -sV -sC -p 53,88,135,139,389,445,636,3268,3389,5985 \
  192.168.90.121 192.168.90.122 192.168.90.123 \
  -oA /tmp/recon_scan
```

### Results

DC 192.168.90.121:

```
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn
389/tcp  open  ldap          Domain: lab.local
445/tcp  open  microsoft-ds
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Domain: lab.local
3389/tcp open  ms-wbt-server CN=windows-ad-dc.lab.local
5985/tcp open  http          Microsoft HTTPAPI 2.0
```

win-agent-01 192.168.90.122:

```
53,88,135,139,389,445,636,3268  filtered
3389/tcp open  ms-wbt-server CN=win-agent-01.lab.local
5985/tcp open  http
```

win-agent-02 192.168.90.123:

```
53,88,135,139,389,445,636,3268  filtered
3389/tcp open  ms-wbt-server CN=win-agent-02.lab.local
5985/tcp open  http
```

### Attack Surface Summary

| Target               | SMB 445  | RPC 135  | WinRM 5985 | Kerberos 88 |
|----------------------|----------|----------|------------|-------------|
| DC 192.168.90.121    | OPEN     | OPEN     | OPEN       | OPEN        |
| Agent 192.168.90.122 | FILTERED | FILTERED | OPEN       | FILTERED    |
| Agent 192.168.90.123 | FILTERED | FILTERED | OPEN       | FILTERED    |

WinRM on port 5985 is the only viable remote execution path to the agents.

## 1.2 LDAP Enumeration

```bash
pip3 install ldapdomaindump
mkdir -p /tmp/ldap_dump

ldapdomaindump -u 'lab.local\john.doe' -p 'Winter2024!' \
  ldap://192.168.90.121 -o /tmp/ldap_dump/
```

Output:

```
Connecting to host...
Binding to host
Bind OK
Starting domain dump
Domain dump finished

Files created: domain_users, domain_groups, domain_computers, domain_policy, domain_trusts
Each in html, json, and grep formats
```

## 1.3 BloodHound Collection

```bash
pip3 install bloodhound

bloodhound-python -u 'john.doe' -p 'Winter2024!' \
  -d lab.local -ns 192.168.90.121 -c All --zip
```

Output:

```
Found AD domain: lab.local
Found 1 domains
Found 1 domains in the forest
Found 3 computers
Found 7 users
Found 52 groups
Found 3 gpos
Found 2 ous
Found 19 containers
Found 0 trusts
Done in 00M 05S
Compressing output into 20260619151704_bloodhound.zip
```

## Wazuh Detection

| Event ID | Description                               | Count    |
|----------|-------------------------------------------|----------|
| 4624     | Network logon from john.doe to DC         | Multiple |
| 4662     | Directory Service Access via LDAP queries | Multiple |
| 5145     | Network share access to SYSVOL and IPC    | Multiple |

Dashboard query to spot this activity:

```
data.win.system.eventID:4624 AND data.win.eventdata.targetUserName:john.doe AND data.win.eventdata.logonType:3
```
