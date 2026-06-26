# Changelog

## v2.1 — Live re-validation (June 25, 2026)

A second live run was performed to re-capture evidence and verify the v2 claims against the
running cluster. Several v1/v2 statements did not survive contact with the live system and are
corrected here. This section is kept deliberately honest — the corrections are part of the
engineering record.

### Confirmed live
- **DCSync (`110001`, event 4662).** Fired at level 12 with mail alert, 57 events on
  `windows-ad-dc` during `secretsdump`. Strongest, cleanest detection in the lab.
- **Password spray (`60122`, event 4625).** 26 failed logons across 17 distinct usernames
  from the attacker tun0 addresses (`192.168.24.2`, `192.168.24.6`) — textbook spray
  signature. High-value names (`krbtgt`, `administrator`, `guest`) appear in the attempt set.

### Corrected
- **LSASS suppression `92901` was NOT live, despite the file being present since June 19.**
  Root cause: `wazuh-manager` had been running for 6 days without a restart, so the rule on
  disk had never been loaded into memory. The v1 claim "LSASS FP suppression 92901, 0 FP
  verified" was therefore not actually verified. After `systemctl restart wazuh-manager`
  the rule loads and no new `92900` alerts appear post-restart.
- **`ossec.conf` ruleset path was fine.** `etc/rules` and `etc/decoders` are correctly
  registered under the user-defined ruleset block — the suppression failure was the missing
  restart, not a missing `rule_dir`.
- **Part of the observed FP drop was an artifact of the attack, not the rule.** Windows
  Defender real-time monitoring had been disabled on the agent during Phase 4
  (`Set-MpPreference -DisableRealtimeMonitoring $true`), which independently stopped MsMpEng
  from touching LSASS. A fully clean before/after of an individual suppressed event still
  awaits the next natural Defender LSASS scan cycle and is listed as a residual gap.
- **Kerberoasting (`4769`) remains not cleanly detectable in this dataset.** A targeted query
  for `serviceName: svc-backup` returned 0 hits; all observed 4769 traffic was normal domain
  service-ticket activity with encryption `0x12` (AES256), not the `0x17` (RC4) roast
  signature. The "visible but not actionable" status from v1 stands.

### Note
The 6-day-uptime / unloaded-rule finding is itself a useful operational lesson: a custom rule
that exists on disk and even passes review is not "deployed" until the manager has reloaded
it. Treat rule deployment as file change **plus** verified reload, not file change alone.

---

## v2 — Detection hardening and coverage closure

### Fixed
- **Decoder anchors.** Rules keyed on events 4662, 4698, 7045, and 4624 were chaining off
  `60103`; corrected to `60109` (the Windows Security-channel decoder root). With the wrong
  anchor the child rules were never evaluated, so events were ingested but never alerted.
  This was the root cause of DCSync only surfacing via the built-in rule `110001`.
- **Format-tolerant value matching.** Exact-string matches (`0x17`, `^0$`, `0x1010`) were
  replaced with zero-pad-tolerant `pcre2` patterns (`^0x0*17$`, etc.). This resolves the
  Kerberoasting "field/value mismatch" that was previously logged but never fixed.
- **Duplicate rule ID.** `92901` existed in both rule files, which makes `wazuh-manager`
  refuse to start. It now lives only in `windows_custom_rules.xml`.

### Added (previously-undetected executed techniques)
- `92761` / `92767` — Microsoft Defender protection disabled (Operational channel + Sysmon
  registry route). T1562.001.
- `92758` — Pass-the-Hash to DC (4624 Type 3 NTLM, keyLength 0), now correctly anchored and
  active.
- `92763` — Forged/Golden ticket **rejection** (4769 status `0x1F`/`0x1B`/`0x29`). Corrects
  the earlier conclusion that rejected Golden Ticket attempts were undetectable; the KDC
  rejection itself is the signal.
- `92764` — Domain password policy weakened (4739).
- `92765` — Account flipped to DONT_REQUIRE_PREAUTH (4738) — AS-REP target creation.
- `92766` — Privileged group membership change (4728/4732/4756 to RID 512/518/519).

### Changed
- `92750` (recon) converted to a frequency rule (15 × 4662 in 30s from one principal).
- `enable-audit-policy.ps1` expanded to enable every subcategory the new rules depend on,
  plus guidance to forward the Defender Operational channel in each agent `ossec.conf`.
- Added `docs/08-coverage-gap-addendum.md` with the full technique → detection matrix,
  deployment order, and honest residual gaps.
- Added `sigma/` — 16 vendor-neutral Sigma rules mirroring the Wazuh detections, with a
  conversion guide for Splunk/Sentinel/Elastic/QRadar and a folder README.

### Security hygiene
- Redacted krbtgt and Administrator credential material (NTLM/AES) throughout the public
  copy. Hashes are shown truncated with a `[REDACTED-…]` marker so evidence structure is
  preserved without publishing usable secrets.

## v1 — Initial lab
- End-to-end AD red-team kill chain (6 phases) with Wazuh detection review, custom rules
  `92750-92760`, LSASS FP suppression `92901`, and per-phase documentation.
