"""Original preflight checks plus offline update failure/lifecycle checks.

No real network, Docker or authentic signature assertion in these new tests.
The explicit real scanner command has a separate evidence report.
"""
from pathlib import Path
import runpy
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import clamav_signature_update as updater


class FakeDocker:
    """Only models lifecycle/files; it never validates a real CVD signature."""
    def __init__(self, root, failure=None):
        self.root, self.failure = root, failure
        self.calls, self.containers, self.networks = [], {}, set()

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:2] == ('network', 'create'):
            self.networks.add(args[2])
        elif args[:2] == ('network', 'rm'):
            self.networks.remove(args[2])
        elif args[0] == 'create':
            name = args[args.index('--name') + 1]
            self.containers[name] = args
        elif args[:2] == ('rm', '-f'):
            del self.containers[args[-1]]
        elif args[0] == 'inspect':
            return '0'
        elif args[0] == 'start':
            command = self.containers[args[2]]
            entry = command[command.index('--entrypoint') + 1]
            if entry == '/bin/sh':
                for db in updater.DATABASES:
                    (self.root / 'updated-signatures' / (db + '.cvd')).write_bytes(b'SYNTHETIC_CVD_' + db.encode())
            elif entry == '/usr/bin/freshclam':
                if self.failure:
                    raise self.failure
                (self.root / 'updated-signatures/daily.cvd').write_bytes(b'SYNTHETIC_UPDATED_CVD')
            elif entry == '/usr/bin/sigtool':
                return 'Build time: 29 Oct 2026 01:00 +0000\nVersion: 123\nSignatures: 12\nVerification OK.'
        return ''


class UpdateTests(unittest.TestCase):
    def test_upstream_head_403_delegates_to_one_real_client_attempt(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError(updater.UPDATE_URL, 403, 'synthetic CDN refusal', {}, None)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docker = FakeDocker(root)
            with patch.object(updater.urllib.request, 'build_opener', return_value=opener):
                directory, summary = updater.update_snapshot(root, docker, 'SYNTHETIC_IMAGE')
            self.assertEqual(summary['connectivity_diagnostic']['http_status'], 403)
            freshclam = [args for args, _ in docker.calls if args[0] == 'create' and '/usr/bin/freshclam' in args]
            self.assertEqual(len(freshclam), 1)
            self.assertFalse(docker.containers or docker.networks)
            self.assertTrue(summary['freshness_requires_live_preflight'])

    def test_real_updater_refusal_does_not_fall_back_to_old_databases(self):
        failure = RuntimeError('SYNTHETIC private proxy details')
        failure.http_status = 403
        with tempfile.TemporaryDirectory() as tmp:
            docker = FakeDocker(Path(tmp), failure)
            with patch.object(updater, 'ensure_update_access', return_value={'http_status': 403}):
                with self.assertRaises(updater.UpdateError) as result:
                    updater.update_snapshot(Path(tmp), docker, 'SYNTHETIC_IMAGE')
            summary = result.exception.summary()
            self.assertEqual(summary['stage'], 'freshclam')
            self.assertEqual(summary['http_status'], 403)
            self.assertEqual(summary['reason'], 'OFFICIAL_SERVER_REFUSED')
            self.assertFalse(summary['updated'])
            self.assertNotIn('private', str(summary))
            self.assertFalse(docker.containers or docker.networks)

    def test_tls_and_exact_official_head(self):
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with patch.object(updater.urllib.request, 'build_opener', return_value=opener) as build:
            updater.ensure_update_access()
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, updater.UPDATE_URL)
        self.assertEqual(request.get_method(), 'HEAD')
        context = build.call_args.args[0]._context
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertLessEqual(opener.open.call_args.kwargs['timeout'], 15)

    def test_connect_policy_denial_stops_before_any_docker_or_files(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.URLError('Tunnel connection failed: 403 Forbidden synthetic-proxy-secret')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docker = Mock()
            with patch.object(updater.urllib.request, 'build_opener', return_value=opener):
                with self.assertRaises(updater.UpdateError) as failure:
                    updater.update_snapshot(root, docker, 'SYNTHETIC_IMAGE')
            self.assertEqual(failure.exception.summary()['http_status'], 403)
            self.assertFalse(failure.exception.summary()['updated'])
            self.assertNotIn('synthetic-proxy-secret', str(failure.exception.summary()))
            docker.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_http_error_and_tls_error_fail_closed(self):
        for error in (urllib.error.HTTPError(updater.UPDATE_URL, 429, 'synthetic', {}, None),
                      urllib.error.URLError(ssl.SSLError('synthetic certificate failure'))):
            with self.subTest(error=type(error).__name__):
                opener = Mock()
                opener.open.side_effect = error
                with patch.object(updater.urllib.request, 'build_opener', return_value=opener):
                    with self.assertRaises(updater.UpdateError):
                        updater.ensure_update_access()

    def test_redirect_is_not_followed(self):
        with self.assertRaises(updater.UpdateError) as failure:
            updater.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://unapproved.invalid/')
        self.assertEqual(failure.exception.reason, 'REDIRECT_REFUSED')

    def test_existing_snapshot_is_never_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'updated-signatures').mkdir()
            keep = root / 'updated-signatures/keep.txt'
            keep.write_text('SYNTHETIC KEEP')
            docker = Mock()
            with patch.object(updater, 'ensure_update_access'):
                with self.assertRaises(FileExistsError):
                    updater.update_snapshot(root, docker, 'SYNTHETIC_IMAGE')
            docker.assert_not_called()
            self.assertEqual(keep.read_text(), 'SYNTHETIC KEEP')

    def test_update_snapshot_and_container_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docker = FakeDocker(root)
            with patch.object(updater, 'ensure_update_access'):
                directory, summary = updater.update_snapshot(root, docker, 'SYNTHETIC_IMAGE')
            self.assertTrue(summary['completed'])
            self.assertTrue(summary['updated'])
            self.assertTrue(summary['freshness_requires_live_preflight'])
            self.assertEqual(len(summary['after']), 3)
            self.assertFalse(docker.containers or docker.networks)
            creates = [args for args, _ in docker.calls if args[0] == 'create']
            for args in creates:
                self.assertIn('--read-only', args)
                self.assertIn('1000:1000', args)
                self.assertIn('no-new-privileges', args)
                self.assertNotIn('--publish', args)
                self.assertNotIn('--privileged', args)
                self.assertNotIn('host', args)
            removals = [args for args, _ in docker.calls if args[0] == 'rm']
            self.assertTrue(all('--volumes' in args for args in removals))
            freshclam = next(args for args in creates if '/usr/bin/freshclam' in args)
            self.assertIn('CURL_CA_BUNDLE=/run/public-ca.pem', freshclam)
            self.assertIn('--no-dns', freshclam)
            self.assertNotIn('--daemon', freshclam)
            self.assertEqual((directory / 'daily.cvd').read_bytes(), b'SYNTHETIC_UPDATED_CVD')
            self.assertEqual(summary['source'], updater.UPDATE_URL)

    def test_update_timeout_removes_owned_container_and_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docker = FakeDocker(root, subprocess.TimeoutExpired('SYNTHETIC_FRESHCLAM', 1))
            with patch.object(updater, 'ensure_update_access'):
                with self.assertRaises(updater.UpdateError) as failure:
                    updater.update_snapshot(root, docker, 'SYNTHETIC_IMAGE')
            self.assertEqual(failure.exception.reason, 'UPDATER_FAILED')
            self.assertFalse(docker.containers or docker.networks)

    def test_unverified_cvd_is_rejected_and_verifier_removed(self):
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            return '0' if args[0] == 'inspect' else 'Verification FAILED.'
        with self.assertRaises(updater.UpdateError) as failure:
            updater.verify_databases(docker, 'SYNTHETIC_IMAGE')
        self.assertEqual(failure.exception.reason, 'CVD_SIGNATURE_FAILED')
        self.assertEqual(calls[-1][:2], ('rm', '-f'))
        create = calls[0]
        self.assertEqual(create[create.index('--network') + 1], 'none')

    def test_symlinked_database_is_rejected_before_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'other').write_bytes(b'SYNTHETIC')
            (root / 'main.cvd').symlink_to(root / 'other')
            docker = Mock()
            with self.assertRaises(updater.UpdateError):
                updater.verify_databases(docker, 'SYNTHETIC_IMAGE', root)
            docker.assert_not_called()


if __name__ == '__main__':
    # Keep every original assertion intact and execute it as before in group 12.
    sys.path.insert(0, str(ROOT / 'tests/ft8'))
    runpy.run_path(str(ROOT / 'tests/ft8/test_clamd_preflight.py'), run_name='__main__')
    unittest.main(argv=[sys.argv[0]], verbosity=2)
