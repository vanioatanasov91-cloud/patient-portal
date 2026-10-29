"""Keep original candidate assertions, then test pilot guards without Docker.

All files/records are synthetic. Fake CVD bytes model only state/hashes; they
are never claimed to have authentic signatures or used by a real scanner.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'app'), str(ROOT / 'tools'), str(ROOT / 'tests/ft10')]
import pilot_runtime as pilot
from candidate_runtime import CandidateError
from clamav_signature_update import UpdateError
from scanner_readiness import signature_is_fresh, PilotScannerCheck
from test_candidate_workflow import run_cli, Fields


class FakeScanner(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    mode = 'fresh'
    scans = 0


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        def exact(n):
            result = bytearray()
            while len(result) < n:
                data = self.request.recv(n - len(result))
                if not data:
                    raise OSError()
                result.extend(data)
            return bytes(result)
        try:
            command = bytearray()
            while not command.endswith(b'\0') and len(command) < 40:
                command.extend(exact(1))
            if command == b'zVERSION\0':
                offset = {'fresh': -1, 'stale': -49, 'future': 1, 'truncated': -1}[self.server.mode]
                stamp = datetime.now(timezone.utc) + timedelta(hours=offset)
                reply = ('ClamAV SYNTHETIC/123/' + stamp.strftime('%a %b %d %H:%M:%S %Y')).encode()
                self.request.sendall(reply + (b'' if self.server.mode == 'truncated' else b'\0'))
                return
            if command != b'zINSTREAM\0':
                return
            while size := struct.unpack('!I', exact(4))[0]:
                exact(size)
            self.server.scans += 1
            self.request.sendall(b'stream: OK\0')
        except (OSError, KeyError):
            pass


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix='FT14_SYNTHETIC_PILOT_') as folder:
        root = Path(folder)
        root.chmod(0o700)
        with FakeScanner(('127.0.0.1', 0), Handler) as scanner:
            thread = threading.Thread(target=scanner.serve_forever, daemon=True)
            thread.start()
            try:
                port = scanner.server_address[1]
                result = run_cli('init', '--data-dir', str(root / 'candidate'), '--scanner-port', str(port), '--confirm-synthetic-only')
                assert result.returncode == 0
                pilot.private_write(root / 'pilot.lock', '0')
                pilot.private_write(root / 'clamd.conf', pilot.CONF)
                relative = 'snapshots/' + secrets.token_hex(16) + '/updated-signatures'
                directory = root / relative
                directory.mkdir(parents=True, mode=0o700)
                records = []
                for name in ('main', 'daily', 'bytecode'):
                    data = b'SYNTHETIC FAKE CVD FOR STATE TEST ONLY: ' + name.encode()
                    (directory / (name + '.cvd')).write_bytes(data)
                    records.append({'database': name, 'verified': True, 'sha256': hashlib.sha256(data).hexdigest()})
                config = {'kind': pilot.KIND, 'version': 1, 'state': 'ready', 'synthetic_only': True,
                          'release_gate': pilot.GATE, 'image': pilot.IMAGE, 'instance_id': secrets.token_hex(16),
                          'http_port': free_port(), 'scanner_port': port,
                          'signature_dir': relative, 'databases': records}
                pilot.private_write(root / 'pilot.json', json.dumps(config))
                yield root, config, scanner
            finally:
                scanner.shutdown()
                thread.join(timeout=5)


@contextmanager
def serving_http(root, config):
    import httpx
    with (root / 'synthetic-http.log').open('wb') as log:
        child = subprocess.Popen([sys.executable, '-B', str(ROOT / 'tools/run_pilot.py'), '_http', '--pilot-dir', str(root)],
                                 stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 25
            while True:
                if child.poll() is not None:
                    raise AssertionError('shipping pilot HTTP entry exited')
                try:
                    with httpx.Client(trust_env=False, timeout=1) as client:
                        if client.get(f'http://127.0.0.1:{config["http_port"]}/login').status_code == 200:
                            break
                except httpx.HTTPError:
                    pass
                if time.monotonic() > deadline:
                    raise AssertionError('shipping pilot HTTP startup timeout')
                time.sleep(0.1)
            yield
        finally:
            pilot.stop_child(child)


class ScannerTests(unittest.TestCase):
    def test_fixed_48h_age_and_malformed_version(self):
        now = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
        for hours, expected in ((0, True), (-48, True), (-49, False), (1, False)):
            stamp = now + timedelta(hours=hours)
            reply = ('ClamAV 1.5.4/123/' + stamp.strftime('%a %b %d %H:%M:%S %Y')).encode()
            self.assertIs(signature_is_fresh(reply, now=now), expected)
        for reply in (b'', b'ClamAV bad', b'ClamAV 1/2/no timestamp', b'\xff'):
            self.assertFalse(signature_is_fresh(reply, now=now))


@unittest.skipUnless(sys.platform == 'linux' and os.getuid() == 1000, 'Linux pilot guards require UID1000')
class PilotTests(unittest.TestCase):
    def test_port_check_refuses_active_listener(self):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', 0))
            sock.listen()
            with self.assertRaises(OSError):
                pilot.free_loopback(sock.getsockname()[1])

    def test_state_refuses_modified_gate_extra_database_and_hash(self):
        with fixture() as (root, config, scanner):
            pilot.read_pilot(root)
            bad = dict(config, release_gate='GO')
            pilot.write_marker(root, bad)
            with self.assertRaises(pilot.PilotError):
                pilot.read_pilot(root)
            pilot.write_marker(root, config)
            extra = root / config['signature_dir'] / 'unsigned.ndb'
            extra.write_text('SYNTHETIC EXTRA DATABASE')
            with self.assertRaises(UpdateError):
                pilot.read_pilot(root)
            extra.unlink()
            (root / config['signature_dir'] / 'daily.cvd').write_bytes(b'SYNTHETIC TAMPER')
            with self.assertRaises(pilot.PilotError):
                pilot.read_pilot(root)

    def test_active_lock_refuses_refresh_and_second_owner_without_docker(self):
        with fixture() as (root, config, scanner):
            with pilot.exclusive(root):
                with patch.object(pilot, 'docker') as docker:
                    with self.assertRaises(pilot.PilotError):
                        pilot.refresh(root)
                    docker.assert_not_called()
                result = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/run_pilot.py'),
                                         'refresh', '--pilot-dir', str(root), '--confirm-offline-synthetic-pilot'],
                                        capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
            with pilot.exclusive(root):
                pass

    def test_reinit_production_and_source_refuse_before_docker(self):
        with fixture() as (root, config, scanner):
            with patch.object(pilot, 'docker') as docker:
                with self.assertRaises(FileExistsError):
                    pilot.initialize_pilot(root)
                with patch.dict(os.environ, {'PORTAL_ENV': 'production'}):
                    with self.assertRaises(pilot.PilotError):
                        pilot.initialize_pilot(root / 'forbidden')
                with self.assertRaises((pilot.PilotError, CandidateError)):
                    pilot.initialize_pilot(ROOT / 'forbidden-pilot')
                docker.assert_not_called()
            self.assertFalse((root / 'forbidden').exists())
            self.assertFalse((ROOT / 'forbidden-pilot').exists())

    def test_update_cooldown_keeps_previous_snapshot(self):
        with fixture() as (root, config, scanner):
            config['last_update_attempt_utc'] = datetime.now(timezone.utc).isoformat()
            pilot.write_marker(root, config)
            with patch.object(pilot, 'docker') as docker:
                with self.assertRaises(pilot.PilotError):
                    pilot.refresh(root)
                docker.assert_not_called()
            self.assertEqual(pilot.read_pilot(root)[1]['signature_dir'], config['signature_dir'])

    def test_cleanup_refuses_unrelated_container(self):
        config = {'instance_id': 'a' * 32}
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[:2] == ('container', 'ls'):
                return 'SYNTHETIC_ID'
            if args[:2] == ('container', 'inspect'):
                return json.dumps([{'Config': {'Labels': {}, 'Image': pilot.IMAGE}}])
            raise AssertionError('unrelated resource operation')
        with patch.object(pilot, 'docker', side_effect=docker):
            with self.assertRaises(pilot.PilotError):
                pilot.clean_owned(config)
        self.assertFalse(any(a[0] in ('rm', 'stop') for a in calls))

    def test_shipping_http_guard_and_restart(self):
        import httpx
        with fixture() as (root, config, scanner):
            accounts = json.loads((root / 'candidate/synthetic-accounts.json').read_text())['accounts']
            with httpx.Client(base_url=f'http://127.0.0.1:{config["http_port"]}', trust_env=False, timeout=12) as client:
                with serving_http(root, config):
                    client.get('/login')
                    token = client.cookies.get('login_csrf')
                    account = accounts[0]
                    self.assertEqual(client.post('/login', data={**{k: account[k] for k in ('username', 'password')}, 'login_token': token}).status_code, 303)
                    with sqlite3.connect(root / 'candidate/candidate.sqlite3') as db:
                        legacy, patient = db.execute('SELECT id,patient_id FROM reports').fetchone()
                    fields = Fields()
                    fields.feed(client.get(f'/patients/{patient}').text)
                    form = {'csrf': fields.csrf, 'title': 'Синтетичен пилот', 'modality': 'ЯМР', 'exam_date': '2020-01-01', 'confirm_owner': 'yes'}
                    from reportlab.pdfgen import canvas
                    output = io.BytesIO()
                    pdf = canvas.Canvas(output)
                    pdf.drawString(60, 700, 'SYNTHETIC PILOT CONTROL')
                    pdf.save()
                    body = output.getvalue()
                    def upload():
                        return client.post(f'/patients/{patient}/reports', data=form, files={'file': ('synthetic.pdf', body, 'application/pdf')})
                    for mode in ('stale', 'future', 'truncated'):
                        scanner.mode = mode
                        before = scanner.scans
                        self.assertEqual(upload().status_code, 503)
                        self.assertEqual(scanner.scans, before)
                        self.assertEqual(len(list((root / 'candidate/files').glob('*.pdf'))), 1)
                    scanner.mode = 'fresh'
                    self.assertEqual(upload().status_code, 303)
                    with sqlite3.connect(root / 'candidate/candidate.sqlite3') as db:
                        document = db.execute('SELECT MAX(id) FROM reports').fetchone()[0]
                    scanner.mode = 'stale'
                    self.assertEqual(client.get(f'/reports/{document}/preview').content, body)
                    self.assertEqual(client.post(f'/reports/{legacy}/scan', data={'csrf': fields.csrf}).status_code, 503)
                    scanner.mode = 'fresh'
                    self.assertEqual(client.post(f'/reports/{legacy}/scan', data={'csrf': fields.csrf}).status_code, 303)
                    with patch.object(pilot, 'docker') as docker:
                        with self.assertRaises(CandidateError):
                            pilot.refresh(root)
                        docker.assert_not_called()
                with serving_http(root, config):
                    self.assertEqual(client.get('/dashboard').status_code, 200)
                    self.assertEqual(client.get(f'/reports/{document}/preview').content, body)


if __name__ == '__main__':
    original = subprocess.run([sys.executable, '-B', str(ROOT / 'tests/ft10/test_candidate_workflow.py')], cwd=ROOT)
    if original.returncode:
        raise SystemExit(original.returncode)
    unittest.main(argv=[sys.argv[0]], verbosity=2)
