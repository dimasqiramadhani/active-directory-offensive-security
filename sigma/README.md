# Sigma Rules — Portable Detections for the AD Red-Team Kill Chain

These are vendor-neutral [Sigma](https://github.com/SigmaHQ/sigma) versions of the Wazuh
detections in `../rules/windows_redteam_detection.xml` (v2). Sigma lets the same detection
logic compile to Splunk SPL, Microsoft Sentinel KQL, Elastic/OpenSearch DSL, QRadar AQL,
and others via `sigma convert`, so the coverage is portable across SIEMs rather than locked
to one platform.

## Rule index

| File | Technique | MITRE | Severity |
|---|---|---|---|
| 01_bloodhound_ldap_recon | High-volume 4662 enumeration | T1087.002 | high |
| 02_password_spray | 4625 spray correlation | T1110.003 | high |
| 03_suspicious_powershell | AMSI bypass / cradle / encoded | T1059.001 | high |
| 04_scheduled_task_persistence | 4698 task creation | T1053.005 | medium |
| 05_registry_run_key_persistence | Sysmon 13 Run key | T1547.001 | medium |
| 06_kerberoasting | 4769 RC4 (0x17) | T1558.003 | high |
| 07_asrep_roasting | 4768 no pre-auth | T1558.004 | high |
| 08_lsass_access | Sysmon 10 vs lsass.exe | T1003.001 | critical |
| 09_pass_the_hash | 4624 T3 NTLM key 0 | T1550.002 | high |
| 10_service_install_lateral | 7045 service install | T1021.002 | high |
| 11_dcsync | 4662 + replication GUID | T1003.006 | critical |
| 12_defender_tamper | Defender disabled (5001 / reg) | T1562.001 | high |
| 13_forged_ticket_rejection | 4769 status 0x1F/0x1B/0x29 | T1558.001 | high |
| 14_password_policy_downgrade | 4739 policy change | T1484.001 | medium |
| 15_asrep_target_creation | 4738 DONT_REQ_PREAUTH | T1558.004 | medium |
| 16_privileged_group_change | 4728/4732/4756 to 512/518/519 | T1098 | high |

## Converting to your SIEM

Install the Sigma CLI and the backend you need, then convert. Examples:

```bash
pip install sigma-cli
sigma plugin install splunk
sigma plugin install elasticsearch

# Splunk SPL
sigma convert -t splunk -p sysmon sigma/

# Elastic / OpenSearch (Lucene)
sigma convert -t lucene -f dsl_lucene sigma/

# Microsoft Sentinel (KQL)
sigma plugin install microsoft365defender
sigma convert -t kusto sigma/
```

## Tuning notes carried over from the Wazuh ruleset

- **Field-name parity.** Sigma field names follow the SigmaHQ Windows taxonomy
  (`SubjectUserName`, `TicketEncryptionType`, `GrantedAccess`, etc.). When converting,
  apply the appropriate `pysigma` pipeline (e.g. `-p sysmon`) so fields map to your data
  model. Mismatched field names are the single most common reason a converted rule stays
  silent — the same lesson that broke the Kerberoasting rule in v1.
- **Value formats.** Several rules list both padded and unpadded hex values
  (`0x17` and `0x00000017`) because Windows renders these inconsistently across sources.
- **Frequency rules.** Sigma's correlation syntax (rules 01 and 02) is newer; if your
  backend predates Sigma correlation support, implement the count/threshold in the SIEM
  natively and keep the YAML as documentation of intent.
- **Audit dependencies.** These detections still require the audit subcategories enabled by
  `../scripts/enable-audit-policy.ps1`. A perfect rule on an unaudited event never fires.

## Honest scope

These mirror the Wazuh detections one-to-one; they do not add new detection capability beyond
what is documented in `../docs/08-coverage-gap-addendum.md`. The forged-ticket detection (13)
covers the *rejection* path observed on Windows Server 2022. Detecting a fully-validating
forged ticket still needs a directory-membership lookup, which Sigma alone cannot express —
left as a documented follow-up.
