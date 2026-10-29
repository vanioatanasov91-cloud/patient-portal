"""Owned, temporary FreshClam snapshots for the explicit Linux scanner lab.

No service installation, mirror override, live database mutation or persistent
updater. Preserve inherited proxies, TLS and CVD signature verification. Raw
network/updater output must never be written to reports or the console.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import secrets
import ssl
import urllib.error
import urllib.request

UPDATE_URL = 'https://database.clamav.net/daily.cvd'
CA_BUNDLE = Path('/etc/ssl/certs/ca-certificates.crt')
DATABASES = ('main', 'daily', 'bytecode')
FRESHCLAM_CONFIG = '''DatabaseDirectory /update-db
DatabaseMirror database.clamav.net
ScriptedUpdates no
TestDatabases yes
Bytecode yes
MaxAttempts 1
ConnectTimeout 10
ReceiveTimeout 30
LogVerbose no
'''
# Full signed CVDs keep independent sigtool verification possible. This is an
# ephemeral test snapshot; it is not the recommended long-running CDIFF setup.


class UpdateError(RuntimeError):
    def __init__(self, stage, reason, http_status=None):
        super().__init__(reason)
        self.stage, self.reason, self.http_status = stage, reason, http_status

    def summary(self):
        return {'status': 'BLOCKED/HOLD', 'stage': self.stage,
                'reason': self.reason, 'http_status': self.http_status,
                'updated': False}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UpdateError('connectivity', 'REDIRECT_REFUSED', code)


def ensure_update_access():
    """Bounded HEAD diagnostic; CONNECT/TLS failure stops before Docker.

    An upstream 403 can reject this generic client while permitting FreshClam.
    Delegate it to one unmodified FreshClam attempt through the same proxy.
    Its authenticated update and live freshness check remain mandatory.
    """
    context = ssl.create_default_context(cafile=str(CA_BUNDLE))
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
    request = urllib.request.Request(UPDATE_URL, method='HEAD')
    try:
        with opener.open(request, timeout=15) as reply:
            if reply.status != 200:
                raise UpdateError('connectivity', 'HTTP_REFUSED', reply.status)
            return {'http_status': 200, 'freshclam_attempt_required': True}
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            return {'http_status': 403, 'freshclam_attempt_required': True,
                    'diagnostic': 'HTTP_HEAD_REFUSED'}
        raise UpdateError('connectivity', 'HTTP_REFUSED', exc.code) from None
    except (urllib.error.URLError, OSError) as exc:
        # CONNECT policy denials arrive as URLError rather than HTTPError.
        # Retain only a numeric status, never proxy URLs, headers or messages.
        status = 403 if re.search(r'\b403\b', str(exc)) else None
        raise UpdateError('connectivity', 'PROXY_DENIED' if status else 'NETWORK_OR_TLS_FAILED', status) from None


def run_owned(docker, image, prefix, entrypoint, command, *, mounts=(),
              network='none', ca_bundle=False, timeout=60):
    """Remove the exact created container even after command failure/timeout."""
    name = prefix + secrets.token_hex(6)
    args = ['create', '--name', name, '--network', network,
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--user', '1000:1000', '--memory', '2g', '--cpus', '2', '--pids-limit', '64',
            '--log-driver', 'none', '--no-healthcheck',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=256m,mode=1777', '-e', 'TZ=UTC']
    for source, target, readonly in mounts:
        if any(c in str(source) for c in (',', '\n', '\r')):
            raise UpdateError('configuration', 'UNSUPPORTED_MOUNT_PATH')
        args += ['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if readonly else '')]
    if ca_bundle:
        args += ['--mount', f'type=bind,src={CA_BUNDLE},dst=/run/public-ca.pem,readonly',
                 '-e', 'CURL_CA_BUNDLE=/run/public-ca.pem']
    args += ['--entrypoint', entrypoint, image, *command]
    docker(*args)
    try:
        output = docker('start', '--attach', name, timeout=timeout)
        if docker('inspect', '--format', '{{.State.ExitCode}}', name) != '0':
            raise UpdateError('container', 'COMMAND_FAILED')
        return output
    finally:
        docker('rm', '-f', '--volumes', name)


def verify_databases(docker, image, directory=None):
    """Use the pinned engine's verifier, offline, for every complete signed CVD."""
    records = []
    mounts = () if directory is None else ((directory, '/var/lib/clamav', True),)
    for name in DATABASES:
        path = None if directory is None else directory / (name + '.cvd')
        if path is not None and (path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1):
            raise UpdateError('verification', 'INVALID_DATABASE_FILE')
        info = run_owned(docker, image, 'pp-ft12-verify-', '/usr/bin/sigtool',
                         ['--info', '/var/lib/clamav/' + name + '.cvd'], mounts=mounts)
        if not re.search(r'^Verification OK\.$', info, re.M):
            raise UpdateError('verification', 'CVD_SIGNATURE_FAILED')
        fields = dict(re.findall(r'^(Build time|Version|Signatures): (.+)$', info, re.M))
        if set(fields) != {'Build time', 'Version', 'Signatures'}:
            raise UpdateError('verification', 'CVD_METADATA_INVALID')
        record = {'database': name, **fields, 'verified': True}
        if path is not None:
            # Streaming hash avoids reading an entire main.cvd into Python RAM.
            with path.open('rb') as handle:
                record['sha256'] = hashlib.file_digest(handle, 'sha256').hexdigest()
        records.append(record)
    return records


def update_snapshot(root, docker, image):
    """Only accepts the lab's newly generated root; returns an owned snapshot.

    Connectivity refusal creates no container/network. The caller retains the
    snapshot only until its temporary directory exits, and mounts it read-only
    into the scanner. No running clamd database is ever modified.
    """
    connectivity = ensure_update_access()
    directory = root / 'updated-signatures'
    directory.mkdir(mode=0o700)  # exclusive: never accept/reuse existing data
    config = root / 'freshclam-lab.conf'
    with config.open('x', encoding='ascii') as handle:
        handle.write(FRESHCLAM_CONFIG)
    run_owned(docker, image, 'pp-ft12-seed-', '/bin/sh',
              ['-c', 'cp /var/lib/clamav/*.cvd /var/lib/clamav/*.cvd.sign /update-db/'],
              mounts=((directory, '/update-db', False),))
    before = verify_databases(docker, image, directory)
    network = 'pp-ft12-update-' + secrets.token_hex(6)
    docker('network', 'create', network)
    try:
        print('RUNNING: FreshClam official update; proxies, TLS and CVD checks enabled', flush=True)
        run_owned(docker, image, 'pp-ft12-freshclam-', '/usr/bin/freshclam',
                  ['--config-file=/run/freshclam-lab.conf', '--no-dns'],
                  mounts=((directory, '/update-db', False), (config, '/run/freshclam-lab.conf', True)),
                  network=network, ca_bundle=True, timeout=240)
    except UpdateError:
        raise
    except Exception as exc:
        http_status = getattr(exc, 'http_status', None)
        raise UpdateError('freshclam', 'OFFICIAL_SERVER_REFUSED' if http_status else 'UPDATER_FAILED', http_status) from None
    finally:
        docker('network', 'rm', network)
    after = verify_databases(docker, image, directory)
    validate_database_entries(directory)
    return directory, {'requested': True, 'status': 'VERIFIED_SNAPSHOT', 'completed': True,
                       'updated': any(b['sha256'] != a['sha256'] for b, a in zip(before, after)),
                       'connectivity_diagnostic': connectivity,
                       'source': UPDATE_URL, 'before': before, 'after': after,
                       'freshness_requires_live_preflight': True}


def validate_database_entries(directory):
    # clamd loads other database formats too. Reject unsigned additions both
    # after update and on every later pilot startup, including worker entry.
    for path in directory.iterdir():
        permitted = (path.name in {n + '.cvd' for n in DATABASES} or path.name == 'freshclam.dat'
                     or re.fullmatch(r'(main|daily|bytecode)-[0-9]+\.cvd\.sign', path.name))
        if not permitted or path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise UpdateError('verification', 'UNEXPECTED_DATABASE_ENTRY')
