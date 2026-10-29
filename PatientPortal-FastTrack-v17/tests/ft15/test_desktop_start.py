"""Original workflow/pilot assertions plus stdlib desktop bootstrap checks.

Runs on the current Python/OS. Native CMD/Windows ACL/GUI behavior is not
certified here; no real package downloads or host installers in this group.
"""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'app'), str(ROOT / 'tests/ft14')]
import desktop_start as desktop
from test_pilot_workflow import fixture, Fields
from candidate_runtime import CandidateError, read_config


class NativeRunner:
    def __init__(self, root, *, fail=None):
        self.root, self.fail, self.calls = root, fail, []
        self.installed = False

    def __call__(self, command, *, stage, **kwargs):
        self.calls.append(command)
        if '-m' in command and command[command.index('-m') + 1] == 'venv':
            env = self.root / 'venv'
            python = desktop.environment_python(self.root)
            python.parent.mkdir(parents=True)
            python.write_text('SYNTHETIC PLACEHOLDER, NOT EXECUTED')
            (env / 'pyvenv.cfg').write_text('SYNTHETIC TEST ENVIRONMENT')
        elif desktop.PACKAGE_PROBE in command:
            if not self.installed:
                raise desktop.SetupError('SYNTHETIC MISSING PACKAGE')
        elif 'pip' in command:
            if self.fail == 'pip':
                raise desktop.SetupError('SYNTHETIC NATIVE EXIT FAILURE')
            self.installed = True
        elif str(ROOT / 'tools/run_candidate.py') in command:
            actual = [sys.executable, *command[1:]]
            result = subprocess.run(actual, cwd=ROOT, capture_output=True, text=True, timeout=25)
            if result.returncode:
                raise desktop.SetupError('SYNTHETIC CANDIDATE CLI FAILURE')
        return subprocess.CompletedProcess(command, 0, stdout='', stderr='')


class DesktopTests(unittest.TestCase):
    def test_native_failure_stops_before_data_creation(self):
        with tempfile.TemporaryDirectory(prefix='FT15_SYNTHETIC_DESKTOP_') as tmp:
            root, marker = desktop.create_or_read_root(Path(tmp) / 'desktop')
            runner = NativeRunner(root, fail='pip')
            with self.assertRaises(desktop.SetupError):
                desktop.prepare(root, run=runner)
            self.assertFalse((root / 'data').exists())
            self.assertFalse(any('init' in cmd for cmd in runner.calls))

    def test_existing_store_never_reseeds_and_diagnostics_hide_passwords(self):
        with tempfile.TemporaryDirectory(prefix='FT15_SYNTHETIC_DESKTOP_') as tmp:
            root, marker = desktop.create_or_read_root(Path(tmp) / 'desktop')
            runner = NativeRunner(root)
            _, data = desktop.prepare(root, run=runner)
            secret = (data / 'candidate-secret').read_bytes()
            accounts = (data / 'synthetic-accounts.json').read_bytes()
            runner.calls.clear()
            desktop.prepare(root, run=runner)
            self.assertFalse(any('init' in cmd for cmd in runner.calls))
            self.assertEqual((data / 'candidate-secret').read_bytes(), secret)
            self.assertEqual((data / 'synthetic-accounts.json').read_bytes(), accounts)
            report = json.dumps(desktop.diagnose(root, scanner_check=lambda port: False))
            self.assertTrue(desktop.diagnose(root, scanner_check=lambda port: False)['candidate_ready'])
            for account in json.loads(accounts)['accounts']:
                self.assertNotIn(account['password'], report)
            self.assertNotIn(secret.decode().strip(), report)

    def test_unknown_root_and_production_refuse_before_write(self):
        with tempfile.TemporaryDirectory(prefix='FT15_SYNTHETIC_DESKTOP_') as tmp:
            root = Path(tmp)
            keep = root / 'keep.txt'
            keep.write_text('SYNTHETIC EXISTING FILE')
            with self.assertRaises(desktop.SetupError):
                desktop.create_or_read_root(root)
            self.assertEqual(list(root.iterdir()), [keep])
            with patch.dict(os.environ, {'PORTAL_ENV': 'production'}):
                with self.assertRaises(desktop.SetupError):
                    desktop.create_or_read_root(root / 'forbidden')
            self.assertFalse((root / 'forbidden').exists())

    def test_source_directory_refused(self):
        with self.assertRaises(CandidateError):
            desktop.create_or_read_root(ROOT / 'forbidden-desktop')
        self.assertFalse((ROOT / 'forbidden-desktop').exists())

    def test_single_owner_and_modified_gate_refusal(self):
        with tempfile.TemporaryDirectory(prefix='FT15_SYNTHETIC_DESKTOP_') as tmp:
            root, marker = desktop.create_or_read_root(Path(tmp) / 'desktop')
            with desktop.desktop_lease(root, marker):
                with self.assertRaises(desktop.SetupError):
                    with desktop.desktop_lease(root, marker):
                        pass
            with desktop.desktop_lease(root, marker):
                pass
            altered = dict(marker, release_gate='GO')
            (root / 'desktop.json').write_text(json.dumps(altered))
            with self.assertRaises(desktop.SetupError):
                desktop.create_or_read_root(root)

    def test_native_exit_code_is_required(self):
        with self.assertRaises(desktop.SetupError):
            desktop.checked_run([sys.executable, '-c', 'raise SystemExit(7)'], stage='SYNTHETIC COMMAND', capture=True)

    def test_readonly_diagnostics_create_nothing(self):
        with tempfile.TemporaryDirectory(prefix='FT15_SYNTHETIC_DESKTOP_') as tmp:
            root = Path(tmp) / 'not-created'
            result = desktop.diagnose(root, scanner_check=lambda port: False)
            self.assertFalse(result['candidate_ready'])
            self.assertFalse(root.exists())
            self.assertEqual(result['release_gate'], 'HOLD / NO-GO')

    def test_foreign_listener_refused_before_spawn(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', 8000))
            listener.listen()
            with patch.object(desktop.subprocess, 'Popen') as spawn:
                with self.assertRaises(desktop.SetupError):
                    desktop.serve(Path(sys.executable), Path('SYNTHETIC DATA'), popen=spawn)
                spawn.assert_not_called()

    @unittest.skipUnless(os.name != 'nt', 'Current integration validates portable bootstrap on the available Linux host')
    def test_browser_after_real_http_ready_and_freshness_flag(self):
        import httpx
        with fixture() as (root, config, scanner):
            candidate = root / 'candidate'
            accounts = json.loads((candidate / 'synthetic-accounts.json').read_text())['accounts']
            children = []
            command_seen = []
            def spawn(command, **kwargs):
                command_seen.extend(command)
                child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
                children.append(child)
                return child
            urls = []
            def browser(url):
                urls.append(url)
                try:
                    with httpx.Client(base_url='http://127.0.0.1:8000', trust_env=False, timeout=12) as client:
                        self.assertEqual(client.get('/login').status_code, 200)
                        account = accounts[0]
                        token = client.cookies.get('login_csrf')
                        self.assertEqual(client.post('/login', data={**{k: account[k] for k in ('username','password')}, 'login_token': token}).status_code, 303)
                        with sqlite3.connect(candidate / 'candidate.sqlite3') as db:
                            patient = db.execute('SELECT patient_id FROM reports').fetchone()[0]
                        fields = Fields()
                        fields.feed(client.get(f'/patients/{patient}').text)
                        from synthetic_pdf import pdf_bytes
                        body = pdf_bytes('SYNTHETIC WINDOWS BOOTSTRAP HTTP CONTROL')
                        data = {'csrf': fields.csrf, 'title':'Синтетичен тест','modality':'ЯМР','exam_date':'2020-01-01','confirm_owner':'yes'}
                        scanner.mode = 'stale'
                        self.assertEqual(client.post(f'/patients/{patient}/reports', data=data, files={'file':('synthetic.pdf',body,'application/pdf')}).status_code, 503)
                        self.assertEqual(scanner.scans, 0)
                        scanner.mode = 'fresh'
                        self.assertEqual(client.post(f'/patients/{patient}/reports', data=data, files={'file':('synthetic.pdf',body,'application/pdf')}).status_code, 303)
                finally:
                    desktop.stop_owned(children[0])
                return True
            with redirect_stdout(io.StringIO()):
                desktop.serve(Path(sys.executable), candidate, browser=browser, popen=spawn)
            self.assertEqual(urls, [desktop.URL])
            self.assertIn('--require-fresh-scanner', command_seen)
            self.assertIsNotNone(children[0].poll())


if __name__ == '__main__':
    previous = subprocess.run([sys.executable, '-B', str(ROOT / 'tests/ft14/test_pilot_workflow.py')], cwd=ROOT)
    if previous.returncode:
        raise SystemExit(previous.returncode)
    unittest.main(argv=[sys.argv[0]], verbosity=2)
