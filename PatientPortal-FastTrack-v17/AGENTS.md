# Codex instructions — PatientPortal Fast Track 17

This file is deliberate: Codex should read it before changing anything.

## Current state

V17 records user-confirmed Windows15+portable ClamAV16 functional acceptance: readiness screenshot, legacy scan/preview, new upload/publish, owner view/download, other-user denial. This is operator evidence, not independent review. Preserve own FastTrack15 desktop/schema1 and candidate/schema2 data/accounts/settings. New encrypted offline backup/restore-drill wrappers reuse that existing venv and the existing AES-GCM API; restore only to unique new own folders, server only localhost8001. Never overwrite the original data or auto-stop services/processes. Native Windows backup CMD/getpass/drill is not yet confirmed. candidate_runtime.read_config explicitly closes both read-only SQLite handles on success/failure and the newly created lifecycle connection after commit to avoid Windows rename/cleanup locks. All prior test source files, portal.py and crypto format stay unchanged. Group18 preserves old15 assertions and adds11 desktop drill cases. HOLD / NO-GO remains.

This is an **isolated development candidate** continued from Fast Track 9, with a runnable synthetic-only candidate CLI and integrated AV/shared admission, fresh versioned store, guarded startup and restart validation. It is NOT a Windows production installer and NOT approved to process real patient data. The production release gate is `HOLD / NO-GO` regardless of green synthetic tests. Keep that gate until independent deployment, security, privacy, backup, and scanner verification.

## Mandatory safety rules

- **Never** deploy, restart Windows services, open firewall ports, alter ACL/BitLocker, or migrate a real database without an explicit separate operator-approved procedure.
- **Never** import or move real patient records, PDFs, passwords, `.env`, keys, SQLite databases or backup archives into repository/tests/chat. Use only generated synthetic data.
- Do not delete or overwrite working `PatientPortal-FastTrack-v6` folders. Work in v17/a new version or a new branch. Use the existing isolated checkout; do not create a Git worktree unless explicitly requested.
- Preserve established patient/admin workflows, URLs, Bulgarian UI, migrations, templates and all seventeen v10 test groups (including the original v6/v7/v8 groups). Changes to `app/portal.py` must be minimal, reviewed, and regression-tested.
- Preserve fail-closed AV gate for new uploads: production requires clamd; scanner outage/inconclusive result blocks ingestion. `PORTAL_PDF_SCAN_MODE=off` is **development only**.
- **Do not** describe legacy PDF checksum verification as antivirus certification. Fast Track 6 has no durable AV attestation field, even for post-v6 uploads.
- Never allow any script to write to production data by default. For legacy inventory use only operator-confirmed OFFLINE copies.
- The user authorized normal isolated candidate integration: keep AV/shared admission restricted to freshly initialized synthetic-only candidate stores or existing test fixtures, single-host and local-filesystem; never delete/replace lock state while workers are alive. No production activation or proxy/OS limits may be applied implicitly.
- Keep the synthetic test runner's safe-source SHA256 allowlist up to date if modifying bundled tracked source; don't manually hide failures by modifying tests.

## Getting started

Read `CODEX_START_HERE_BG.md`, `README_BG.md`, `ANALYSIS_BG.md`, `NEXT_SPRINT_BG.md`, `LEGACY_AV_DESIGN_BG.md`, `CLAMAV_OPERATIONS_BG.md`, `RESOURCE_POLICY_BG.md`, `SHARED_ADMISSION_BG.md`, `CANDIDATE_START_BG.md`. Use the normal candidate CLI only with new synthetic stores; do not activate it on real data or migrate an existing DB.

Windows (ordinary PowerShell, no Administrator) with dependencies available:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN_ALL_SAFE_TESTS.ps1 -IncludeSynthetic
```

Cross-platform (isolated test Python, not a production runtime):

```bash
python -B tools/fasttrack_runner.py --include-synthetic
```

Expect **18/18 synthetic test groups** (group12 preserves preflight/updater tests and12 portable scanner cases; group17 preserves all42 candidate assertions,8 pilot tests and9 desktop bootstrap cases) (the previous 17 plus authenticated offline candidate backup/restore; group 16 has a bounded 30-second soak). Real ClamAV remains an explicit separate lab/report; freshness evidence is time-bound, `reports/last_fasttrack_run.json`, and `RELEASE GATE: HOLD / NO-GO`.

## Targets and remaining independent checks (v10 candidate integration does not approve production)

1. **Legacy PDF hold / attestation design** — propose a versioned schema migration with explicit AV verdict/source/time/checksum; do not apply to real data. On synthetic fixtures demonstrate how un-attested legacy PDFs could be withheld from patient delivery/publishing while staff receive a safe remediation path. Do not silently revoke or delete existing reports.
2. **Real clamd operational check** — propose operator-run preflight for local-only daemon, signature recency, TCP listener lockdown, log privacy, timeouts and harmless EICAR. The user explicitly authorized the separate real-scanner lab: own containers and synthetic data only; preserve TLS/CVD signatures and delete only owned test resources. Default suite still mocks the scanner. Do not install/configure scanner services as a side effect.
3. **Multi-worker resource policy** — model PDF response memory per worker, new uploads under concurrent load, CPU/memory limits, timeouts and aggregate admission. Build synthetic stress/load harness against an ephemeral isolated test server only, never the installed service.
4. **Release readiness** — checklist for independent review of GDPR/DPIA, Windows ACL/BitLocker, malware scanner process, HTTPS, rate limits, backups/restore, monitoring and audit retention.

## Definition of done for each Codex iteration

- Deliver code and concise Bulgarian changelog; explain limitations and remaining risks.
- Run all offline tests, show actual pass/fail, and update SHA256 source manifests after code changes.
- For each new test use fake names, generated PDFs and temporary SQLite. No production network connections.
- Do not change `HOLD / NO-GO` to approved automatically.
