# Detection Coverage Gap Addendum (Rule Pack v2)

This addendum extends `07-wazuh-detection-report.md`. It maps every technique that was
*executed* in the lab to a *deployed and firing* detection, and records what changed in
the v2 rule pack. The goal: no executed technique should sit at zero coverage.

## Why v1 left gaps

Three classes of problem made v1 under-detect:

1. **Wrong decoder anchor.** Rules for events 4662, 4698, 7045, 4624 chained off `60103`.
   In the stock ruleset those Security-channel events decode under `60109`. With the wrong
   `if_sid` the child rule is never evaluated, so the event is ingested but never alerts.
   This is why DCSync only surfaced via the built-in `110001` and the custom `92760` stayed
   silent.

2. **Exact-string value matches.** `0x17`, `^0$`, `0x1010` were matched literally. Windows
   and Sysmon frequently render these zero-padded (`0x00000017`, `0x00000000`). A single
   format difference makes the rule miss. v2 uses `pcre2` zero-pad-tolerant patterns
   (`^0x0*17$`, etc.). This is the concrete fix for the Kerberoasting "field mismatch" that
   was logged but never resolved.

3. **Executed-but-unmodeled techniques.** Several actions had no rule at all: Defender
   real-time disable, the policy-complexity downgrade, and the forged-ticket rejection.

## Technique -> Detection matrix (v2)

| #   | Technique (executed)            | Event(s)         | Rule (v2)                  | Status after v2         | Dependency                      |
|-----|---------------------------------|------------------|----------------------------|-------------------------|---------------------------------|
| 1   | BloodHound / LDAP recon         | 4662             | 92750 (freq 15/30s)        | Detected (volume)       | DS Access audit + SACL          |
| 2   | Password spray                  | 4625             | 92751 (freq 5/60s)         | Detected (correlated)   | Logon failure audit             |
| 3   | Encoded / cradle PowerShell     | 4104             | 92752                      | Detected                | ScriptBlockLogging              |
| 4   | AMSI bypass                     | 4104             | 92762                      | Detected                | ScriptBlockLogging              |
| 5   | Scheduled task (attempted)      | 4698             | 92753                      | Detected when it fires  | anchor fixed                    |
| 6   | Registry Run key persistence    | Sysmon 13        | 92754                      | Detected                | Sysmon RegistryEvent            |
| 7   | Kerberoasting                   | 4769 (0x17)      | 92755                      | Detected                | value format fixed              |
| 8   | AS-REP roasting                 | 4768 (preauth 0) | 92756                      | Detected                | **Kerberos AS audit (was OFF)** |
| 9   | AS-REP target creation          | 4738             | 92765                      | Detected                | UAC audit                       |
| 10  | LSASS dump                      | Sysmon 10        | 92757 + 92901 suppress     | Detected, FP-suppressed | Sysmon ProcessAccess            |
| 11  | Defender real-time disable      | Defender 5001    | 92761                      | Detected                | **Defender channel forward**    |
| 11b | Defender disable (reg route)    | Sysmon 13        | 92767                      | Detected (backup path)  | Sysmon RegistryEvent            |
| 12  | Pass the Hash to DC             | 4624 T3 NTLM     | 92758                      | Detected                | anchor + value fixed            |
| 13  | Service-install lateral         | 7045             | 92759                      | Detected                | anchor fixed                    |
| 14  | DCSync                          | 4662 + GUID      | 92760 (or built-in 110001) | Detected                | DS Access audit                 |
| 15  | Forged/Golden ticket (rejected) | 4769 status 0x1F | 92763                      | Detected (rejection)    | Kerberos TGS audit              |
| 16  | Password policy downgrade       | 4739             | 92764                      | Detected                | Policy Change audit             |
| 17  | Privileged group change         | 4728/4732/4756   | 92766                      | Detected                | Group Mgmt audit                |

## The Golden Ticket detection, corrected

v1 stated that *if* the ticket had succeeded, a 4769 for the non-existent user `hacker`
would be the indicator, and concluded the rejected attempts were undetectable. That framing
misses the actual telemetry. Because Windows Server 2022 rejected the forged ticket at the
PAC/TGT validation layer, the KDC emitted **4769 with failure status `0x1F`
(KDC_ERR_TGT_REVOKED)**. The realistic detection is therefore on the *rejection*, which rule
`92763` now covers. Related forged-ticket failures: `0x1B` (MUST_USE_USER2USER) and `0x29`
(KRB_AP_ERR_MODIFIED / PAC integrity).

For a fully-validating forged ticket (e.g. Mimikatz in memory), the complementary signal
remains: a 4769 whose `targetUserName` does not resolve to a real directory object, and
abnormally long ticket lifetimes. That logic is left as a documented follow-up because it
needs a directory-membership lookup that a stateless Wazuh rule cannot do alone (better
suited to a scheduled OpenSearch query or the PPL rule engine).

## Deployment order

1. Run `enable-audit-policy.ps1` (v2) on the DC and every member host first. Detections
   without their audit subcategory will never fire regardless of rule quality.
2. Add the Defender Operational channel to each agent `ossec.conf` (block in the script).
3. Deploy `windows_redteam_detection.xml` (v2) and `windows_custom_rules.xml`. Rule `92901`
   now lives only in the custom file; do not reintroduce it into the detection file or the
   manager will refuse to start on duplicate ID.
4. `systemctl restart wazuh-manager`, then re-run each technique and confirm the mapped rule
   fires. Treat "ingested but no alert" as a failed test, not a pass.

## Honest residual gaps

- 92750 recon threshold (15 events / 30s) is a starting heuristic; tune against a baseline
  of normal 4662 volume on the specific DC before trusting it. A quiet lab and a busy
  production DC need different thresholds.
- 92757 LSASS access list of `grantedAccess` masks is not exhaustive; dumpers can request
  other rights. The high-confidence masks are covered; broaden only with FP testing.
- DS Access on 4662 depends on the SACL on the naming context, not just the audit
  subcategory. Verify the SACL exists rather than assuming the subcategory is enough.
