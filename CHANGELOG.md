# Changelog

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
