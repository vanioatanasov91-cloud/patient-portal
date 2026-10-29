"""Explicit first-run acceptance against an unused marked synthetic pilot.

Owns its supervisor processes, never connects to an arbitrary URL. Starts/stops
only this pilot, exercises generated records, then leaves its data for review.
No real network updater is run; preparation must already have succeeded.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time

from pilot_runtime import (ROOT, GATE, LABEL, docker, exclusive, http_ready,
                           read_pilot, resource_names, status, stop_child)
from synthetic_pdf import pdf_bytes, eicar_pdf
from clamd_preflight import probe
sys.path.insert(0, str(ROOT / 'app'))
from shared_pdf_admission import DiskSlotPool
import candidate_backup


class Fields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('name') == 'csrf':
            self.csrf = attrs.get('value')


@contextmanager
def owned_server(root, config, logfile, *, restored=None, port=None):
    command = [sys.executable, '-B', str(ROOT / 'tools/run_pilot.py'), 'serve', '--pilot-dir', str(root)]
    if restored:
        command = [sys.executable, '-B', str(ROOT / 'tools/run_candidate.py'), 'serve', '--data-dir', str(restored), '--port', str(port)]
    fd = os.open(logfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as output:
        child = subprocess.Popen(command, stdout=output, stderr=output, start_new_session=True)
    try:
        target = dict(config, http_port=port) if restored else config
        deadline = time.monotonic() + 90
        while not http_ready(target):
            if child.poll() is not None or time.monotonic() > deadline:
                # The shipping supervisor emits only sanitized operator errors.
                # Retain its log in the private pilot directory for diagnosis.
                diagnostic = root / 'last-acceptance-startup.log'
                if logfile.is_file():
                    fd = os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'w') as output:
                        output.write(logfile.read_text(errors='replace'))
                raise RuntimeError('Owned synthetic server startup failed')
            time.sleep(0.2)
        yield
    finally:
        stop_child(child)


def exercise(path):
    import httpx
    import socket
    root, config = read_pilot(path)
    with exclusive(root):
        pass  # reject an already running pilot before any HTTP writes
    data = root / 'candidate'
    with sqlite3.connect(data / 'candidate.sqlite3') as db:
        if db.execute('SELECT COUNT(*) FROM reports').fetchone()[0] != 1 or db.execute('SELECT COUNT(*) FROM candidate_pdf_av_attestations').fetchone()[0] != 0:
            raise RuntimeError('First-run acceptance requires an unused synthetic candidate; never reseed it')
        legacy, patient_id = db.execute('SELECT id,patient_id FROM reports').fetchone()
    checks = []
    started = datetime.now(timezone.utc).isoformat()
    def check(ok, name):
        checks.append({'check': name, 'passed': bool(ok)})
        print(('PASS: ' if ok else 'FAIL: ') + name, flush=True)
        if not ok:
            raise AssertionError(name)
    result = {'mode': 'REAL LINUX PILOT / OWNED RESOURCES / SYNTHETIC ONLY',
              'release_gate': GATE, 'production_approved': False, 'status': 'FAIL/HOLD', 'started_utc': started}
    try:
        accounts = json.loads((data / 'synthetic-accounts.json').read_text())['accounts']
        with tempfile.TemporaryDirectory(prefix='pilot-acceptance-', dir=root) as temp:
            work = Path(temp)
            base = f'http://127.0.0.1:{config["http_port"]}'
            with httpx.Client(base_url=base, trust_env=False, timeout=15) as staff, \
                 httpx.Client(base_url=base, trust_env=False, timeout=15) as patient, \
                 httpx.Client(base_url=base, trust_env=False, timeout=15) as other:
                with owned_server(root, config, work / 'first.log'):
                    check(status(root)['ready'], 'shipping supervisor, HTTP and real scanner are ready')
                    result['preflight'] = probe(port=config['scanner_port'], signature_timezone='UTC')
                    check(result['preflight']['protocol_passed'], 'real pilot PING/clean/EICAR/48h preflight passes')
                    for client, account in zip((staff, patient, other), accounts):
                        client.get('/login')
                        token = client.cookies.get('login_csrf')
                        check(client.post('/login', data={**{k: account[k] for k in ('username', 'password')}, 'login_token': token}).status_code == 303,
                              'normal synthetic login succeeds')
                    check(patient.get(f'/reports/{legacy}/download').status_code == 423, 'unattested legacy document is held')
                    fields = Fields()
                    fields.feed(staff.get(f'/patients/{patient_id}').text)
                    form = {'csrf': fields.csrf, 'title': 'Синтетичен пилотен документ', 'modality': 'ЯМР', 'exam_date': '2020-01-01', 'confirm_owner': 'yes'}
                    body = pdf_bytes('SYNTHETIC PILOT REAL CLAMAV CONTROL')
                    def upload(payload):
                        return staff.post(f'/patients/{patient_id}/reports', data=form, files={'file': ('synthetic-pilot.pdf', payload, 'application/pdf')})
                    check(upload(body).status_code == 303, 'clean PDF passes per-request readiness and actual INSTREAM scan')
                    with sqlite3.connect(data / 'candidate.sqlite3') as db:
                        document = db.execute('SELECT MAX(id) FROM reports').fetchone()[0]
                        count = db.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
                    check(staff.get(f'/reports/{document}/preview').content == body, 'staff preview matches exact bytes')
                    check(staff.post(f'/reports/{document}/publish', data=form).status_code == 303, 'staff confirms and publishes previewed document')
                    check(patient.get(f'/reports/{document}/download').content == body, 'owner downloads exact published bytes')
                    check(other.get(f'/reports/{document}/download').status_code == 404, 'other patient cannot access document')
                    check(staff.post(f'/reports/{legacy}/scan', data={'csrf': 'SYNTHETIC_INVALID_CSRF'}).status_code == 403, 'legacy rescan requires valid staff CSRF')
                    files = len(list((data / 'files').glob('*.pdf')))
                    check(upload(eicar_pdf()).status_code == 422, 'actual scanner refuses embedded EICAR PDF')
                    with sqlite3.connect(data / 'candidate.sqlite3') as db:
                        check(db.execute('SELECT COUNT(*) FROM reports').fetchone()[0] == count and len(list((data / 'files').glob('*.pdf'))) == files,
                              'malware refusal leaves no report or orphan PDF')
                    pool = DiskSlotPool(data / 'shared-admission/total', 2)
                    first, second = pool.try_acquire(), pool.try_acquire()
                    try:
                        check(first is not None and second is not None, 'acceptance owns both existing PDF admission slots')
                        busy = patient.get(f'/reports/{document}/download')
                        check(busy.status_code == 503 and busy.headers.get('retry-after') == '2', 'real pilot workers respect shared admission and Retry-After')
                    finally:
                        if first:
                            first.close()
                        if second:
                            second.close()
                    cookies = dict(patient.cookies)
                    def download(_):
                        with httpx.Client(base_url=base, trust_env=False, timeout=15, cookies=cookies) as client:
                            reply = client.get(f'/reports/{document}/download')
                            return reply.status_code, reply.content
                    with ThreadPoolExecutor(max_workers=32) as executor:
                        replies = list(executor.map(download, range(32)))
                    check(any(code == 200 for code, _ in replies) and all(code in (200, 503) and (code != 200 or value == body) for code, value in replies),
                          '32 concurrent requests return correct bytes or bounded overload')
                    result['concurrent_status_counts'] = {str(code): sum(c == code for c, _ in replies) for code in (200, 503)}
                    check(staff.post(f'/reports/{legacy}/scan', data={'csrf': fields.csrf}).status_code == 303, 'staff explicitly rescans legacy PDF with real scanner')
                    check(patient.get(f'/reports/{legacy}/download').content == (data / 'files/synthetic-legacy.pdf').read_bytes(), 'rescanned legacy owner delivery succeeds')
                check(not status(root)['ready'], 'controlled stop removes owned runtime and preserves store')
                key = secrets.token_urlsafe(32)
                archive, restored = work / 'synthetic.ppbk', work / 'restored'
                candidate_backup.create(data, archive, key)
                candidate_backup.restore(archive, restored, key)
                check((restored / 'candidate-secret').read_bytes() == (data / 'candidate-secret').read_bytes(), 'offline authenticated restore preserves candidate identity')
                with owned_server(root, config, work / 'second.log'):
                    check(patient.get('/dashboard').status_code == 200 and patient.get(f'/reports/{document}/download').content == body,
                          'normal pilot restart preserves session/document/AV evidence')
                    with socket.socket() as sock:
                        sock.bind(('127.0.0.1', 0))
                        restored_port = sock.getsockname()[1]
                    with owned_server(root, config, work / 'restored.log', restored=restored, port=restored_port):
                        with httpx.Client(base_url=f'http://127.0.0.1:{restored_port}', trust_env=False, timeout=15, cookies=dict(patient.cookies)) as restored_client:
                            check(restored_client.get('/dashboard').status_code == 200 and restored_client.get(f'/reports/{document}/download').content == body,
                                  'restored normal candidate accepts original session and serves real-scanned document')
                            with sqlite3.connect(restored / 'candidate.sqlite3') as db:
                                check(db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'restored pilot database integrity passes')
            container, network = resource_names(config)
            check(not docker('container', 'ls', '-a', '--format', '{{.Names}}', '--filter', 'label=' + LABEL + '=' + config['instance_id']),
                  'acceptance leaves no owned scanner container')
            result['status'] = 'PASS/HOLD'
    except Exception as exc:
        result['error_type'] = type(exc).__name__
        print('FAIL/HOLD: ' + type(exc).__name__, flush=True)
    finally:
        result.update(checks=checks, passed=sum(c['passed'] for c in checks), finished_utc=datetime.now(timezone.utc).isoformat())
        report = ROOT / 'reports/last_pilot_acceptance.json'
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['status'] == 'PASS/HOLD' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Explicit real first-run synthetic pilot acceptance')
    parser.add_argument('--pilot-dir', required=True)
    parser.add_argument('--confirm-synthetic-pilot-exercise', action='store_true', required=True)
    args = parser.parse_args()
    raise SystemExit(exercise(args.pilot_dir))
