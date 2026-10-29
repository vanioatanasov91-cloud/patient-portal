#!/usr/bin/env python3
"""Consolidated SAFE test launcher for Patient Portal FastTrack.

Only processes a bundled, curated copy of the source. It cannot deploy, stop
Windows services, alter ACL or BitLocker, or connect to a production portal.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "last_fasttrack_run.json"
CHECKS = [
    ("static", "Source integrity and syntax", "tools/fasttrack_checks.py"),
    ("dr", "Synthetic disaster recovery", "tests/dr/stage612_fake_dr_test.py"),
    ("ui", "Synthetic UI acceptance", "tests/ui/run_stage610_ui.py"),
    ("security", "Synthetic access and security (59 assertions)", "tests/security/run_stage6151_security.py"),
    ("pdf", "Candidate PDF integrity & publishing", "tests/pdf/test_pdf_hardening.py"),
    ("snapshot", "Verified PDF delivery snapshot (16 checks)", "tests/pdf/test_snapshot_delivery.py"),
    ("admission", "Bounded PDF delivery admission (synthetic)", "tests/pdf/test_delivery_admission.py"),
    ("scan", "Local clamd upload scan gate (25 synthetic checks)", "tests/pdf/test_clamd_scan_gate.py"),
    ("legacy_inventory", "Legacy PDF offline inventory (synthetic)", "tests/pdf/test_legacy_inventory.py"),
    ("concurrency", "Bounded PDF response concurrency (16 synthetic contenders)", "tests/pdf/test_concurrent_delivery.py"),
    ("legacy_policy_v8", "Synthetic legacy AV hold & staff remediation", "tests/ft8/test_legacy_policy.py"),
    ("clamd_preflight_v8", "Original clamd preflight and isolated signature updater (mocked)", "tests/ft12/test_scanner_operations.py"),
    ("http_load_v8", "Ephemeral two-worker HTTP mixed load (32 clients)", "tools/synthetic_http_load.py"),
    ("shared_admission_v9", "Cross-process PDF admission and crash recovery", "tests/ft9/test_shared_admission.py"),
    ("ingress_v9", "ASGI ingress, multipart cleanup and cancellation lifetime", "tests/ft9/test_admission_ingress.py"),
    ("resource_load_v9", "Two-worker large PDF boundaries and 30s bounded soak", "tools/synthetic_resource_load.py"),
    ("candidate_workflow_v10", "Original candidate workflow plus pilot readiness and restart", "tests/ft14/test_pilot_workflow.py"),
    ("candidate_backup_v11", "Authenticated offline candidate backup and restored startup", "tests/ft11/test_candidate_backup.py"),
]


def execute(name: str, label: str, rel: str):
    target = ROOT / rel
    if not target.is_file() or target.is_symlink():
        return {"id":name,"label":label,"status":"FAIL","exit_code":None,
                "elapsed_seconds":0.0,"error":"Test script missing or symlink"}
    start = time.monotonic()
    try:
        completed = subprocess.run([sys.executable, '-B', str(target)], cwd=str(ROOT),
                                   capture_output=True, text=True, encoding='utf-8',
                                   errors='replace', timeout=150, check=False,
                                   env=os.environ.copy())
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"id":name,"label":label,"status":"FAIL","exit_code":None,
                "elapsed_seconds":round(time.monotonic()-start,3),
                "error":type(exc).__name__}
    output = completed.stdout + '\n' + completed.stderr
    # Keep output out of durable JSON: only summary metadata stored on disk.
    record = {"id":name,"label":label,
              "status":"PASS" if completed.returncode == 0 else "FAIL",
              "exit_code":completed.returncode,"elapsed_seconds":round(time.monotonic()-start,3),
              "output_lines":len(output.splitlines()),
              "output_sha256":hashlib.sha256(output.encode('utf-8')).hexdigest()}
    if completed.returncode != 0:
        # Underlying tests use synthetic fixtures. Truncate diagnostic on failure.
        record["error"] = "Test failed; review sanitized synthetic test console output"
        print("TEST FAILURE DETAILS (last lines, synthetic fixture only):",flush=True)
        print('\n'.join(output.splitlines()[-12:]),flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description='Offline curated Patient Portal FastTrack checks')
    parser.add_argument('--include-synthetic',action='store_true')
    args=parser.parse_args()
    # production guard: the PowerShell wrapper also checks these rules.
    if os.name == 'nt':
        path = str(ROOT).lower()
        if path.startswith('c:\\patientportal\\staging\\'):
            print('FAIL/HOLD: Refuse execution from writable staging.',flush=True)
            return 1
    if len({item[0] for item in CHECKS}) != len(CHECKS):
        print("FAIL/HOLD: Duplicate test IDs in safe test launcher", flush=True)
        return 1
    selected = CHECKS if args.include_synthetic else CHECKS[:1]
    records=[]
    print('=== PATIENT PORTAL FAST TRACK 14 / CONSOLIDATED SAFE TESTS ===',flush=True)
    for name, label, rel in selected:
        result=execute(name,label,rel)
        records.append(result)
        print(f"{result['status']}: {label} ({result['elapsed_seconds']:.2f}s)",flush=True)
        if result['status'] != 'PASS':
            break  # fail closed; don't incorrectly report full success
    success=len(records)==len(selected) and all(r['status']=='PASS' for r in records)
    report={"title":"Patient Portal Fast Track 14 — safe test run",
            "timestamp_utc":datetime.now(timezone.utc).isoformat(),
            "test_mode":"OFFLINE SYNTHETIC ONLY" if args.include_synthetic else "STATIC ONLY",
            "source":"modified candidate app/portal.py, not verified installed backend",
            "status":"PASS" if success else "FAIL/HOLD",
            "passed":sum(r['status']=='PASS' for r in records),
            "attempted":len(records),"planned":len(selected),
            "tests":records,"release_gate":"HOLD / NO-GO",
            "production_approved":False,
            "limitations":["No real patient data, production services or ACL are tested",
                           "No independently validated restore", "No independent security or GDPR approval",
                           "This default suite uses mocked scanners; real ClamAV has its separate explicit report",
                           "Offline inventory never checks malware and cannot attest existing files",
                           "Two-worker HTTP smoke uses generated fixtures and scanner OFF; no production capacity claim",
                           "Integrated candidate uses a fresh synthetic store only; no production migration/activation",
                           "Shared admission is single-host; no production proxy or OS limits applied",
                           "Resource sample and 30s soak are not capacity certification or enforced RSS ceilings"]}
    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('SUMMARY: {}/{} planned checks passed'.format(report['passed'], report['planned']),flush=True)
    print('REPORT: reports/last_fasttrack_run.json',flush=True)
    if success:
        print('PASS: FAST TRACK 14 CONSOLIDATED SAFE SUITE COMPLETE',flush=True)
    else:
        print('FAIL/HOLD: FAST TRACK 14 checks incomplete or failed',flush=True)
    print('RELEASE GATE: HOLD / NO-GO. NO PRODUCTION APPROVAL.',flush=True)
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
