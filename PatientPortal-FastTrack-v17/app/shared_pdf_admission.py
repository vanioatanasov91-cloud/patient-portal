"""FT9 single-host OS-lock admission + pure ASGI ingress prototype.

No import-time files, schema changes, installation or production activation.
Only explicit generated fixtures install this layer around the candidate app.
Locks never expire while work may still be running; the OS releases them on exit.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from starlette.formparsers import MultiPartException

if os.name == 'nt':
    import msvcrt
else:
    import fcntl


class AdmissionUnavailable(RuntimeError):
    """Unusable shared state must never silently become unlimited capacity."""


class Lease:
    def __init__(self, fd):
        self.fd = fd

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            # Closing the descriptor releases flock / Windows byte-range locks.
            os.close(fd)

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class DiskSlotPool:
    """Fixed stable lock files on one trusted LOCAL filesystem, not NFS/SMB.

    Do not delete, replace or resize state while any worker is alive. Configuration
    changes require stopping all fixture workers. This is not a distributed lock.
    """
    def __init__(self, folder: Path, capacity: int):
        self.folder = Path(folder)
        self.capacity = capacity
        try:
            if not 1 <= capacity <= 8 or self.folder.is_symlink():
                raise ValueError('invalid pool')
            config = json.loads((self.folder / 'pool.json').read_text())
            if config != {'version': 1, 'capacity': capacity}:
                raise ValueError('pool capacity/version mismatch')
        except (OSError, ValueError, TypeError) as exc:
            raise AdmissionUnavailable('HOLD: unavailable shared admission state') from exc

    @classmethod
    def prepare(cls, folder: Path, capacity: int):
        """Explicit setup, only before workers start; never called by requests."""
        folder = Path(folder)
        if not 1 <= capacity <= 8:
            raise ValueError('capacity must be 1-8')
        folder.mkdir(mode=0o700)
        for index in range(capacity):
            fd = os.open(folder / f'slot-{index}', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as out:
                out.write(b'0')
        (folder / 'pool.json').write_text(json.dumps({'version': 1, 'capacity': capacity}))
        return cls(folder, capacity)

    def try_acquire(self):
        for index in range(self.capacity):
            fd = None
            try:
                path = self.folder / f'slot-{index}'
                if path.is_symlink():
                    raise OSError('symlink slot')
                fd = os.open(path, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size != 1 or info.st_nlink != 1:
                    raise OSError('invalid slot file')
                try:
                    if os.name == 'nt':
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                        raise
                    os.close(fd)
                    fd = None
                    continue
                return Lease(fd)
            except OSError as exc:
                if fd is not None: os.close(fd)
                raise AdmissionUnavailable('HOLD: shared admission lock failure') from exc
        return None


@dataclass(frozen=True)
class IngressLimits:
    # Multipart envelope gets bounded headroom; the PDF itself still has 15 MiB.
    max_body_bytes: int = 15 * 1024 * 1024 + 256 * 1024
    body_idle_seconds: float = 5.0
    body_total_seconds: float = 30.0
    max_form_bytes: int = 64 * 1024


class BodyLimitExceeded(MultiPartException):
    def __init__(self): super().__init__('Synthetic ingress body limit exceeded')


class BodyReadTimedOut(MultiPartException):
    def __init__(self): super().__init__('Synthetic ingress body read timeout')


class BodyReadInterrupted(MultiPartException):
    def __init__(self): super().__init__('Synthetic upload interrupted')


async def reject(send, status, message, retry=False):
    body = message.encode('utf-8')
    headers = [(b'content-type', b'text/plain; charset=utf-8'),
               (b'content-length', str(len(body)).encode()),
               (b'cache-control', b'private, no-store'), (b'x-content-type-options', b'nosniff')]
    if retry: headers.append((b'retry-after', b'2'))
    await send({'type':'http.response.start', 'status':status, 'headers':headers})
    await send({'type':'http.response.body', 'body':body})


def pdf_operation(scope):
    method, path = scope.get('method', ''), scope.get('path', '')
    if method == 'POST' and re.fullmatch(r'/patients/[^/]+/reports/?', path):
        return 'upload'
    if method == 'POST' and re.fullmatch(r'/reports/[^/]+/(publish|scan)/?', path):
        return 'pdf'
    if method in ('GET', 'HEAD') and re.fullmatch(r'/reports/[^/]+/(preview|view|download)/?', path):
        return 'pdf'
    return None


class SharedPdfAdmission:
    def __init__(self, app, total: DiskSlotPool, uploads: DiskSlotPool, limits=IngressLimits()):
        if limits.max_body_bytes < 1 or limits.body_idle_seconds <= 0 or limits.body_total_seconds <= 0 or limits.max_form_bytes < 1:
            raise ValueError('invalid ingress limits')
        self.app, self.total, self.uploads, self.limits = app, total, uploads, limits

    async def __call__(self, scope, receive, send):
        operation = pdf_operation(scope) if scope['type'] == 'http' else None
        if operation is None:
            return await self.app(scope, receive, send)
        leases = []
        try:
            try:
                for pool in (self.total, self.uploads) if operation == 'upload' else (self.total,):
                    lease = pool.try_acquire()
                    if lease is None:
                        return await reject(send, 503, 'Временно ограничение на PDF заявките. Опитайте отново.', True)
                    leases.append(lease)
            except AdmissionUnavailable:
                return await reject(send, 503, 'PDF обработката временно не е достъпна.', True)

            # Reject declared oversize BEFORE calling app or consuming any body.
            # This also rejects ambiguous lengths; byte counting protects chunked
            # and understated Content-Length at the ASGI boundary.
            bounded_body = scope.get('method') == 'POST'
            body_limit = self.limits.max_body_bytes if operation == 'upload' else self.limits.max_form_bytes
            if bounded_body:
                lengths = [v for k,v in scope.get('headers', []) if k.lower() == b'content-length']
                if len(lengths) > 1 or (lengths and not re.fullmatch(rb'[0-9]{1,20}', lengths[0])):
                    return await reject(send, 400, 'Невалидна дължина на заявката.')
                if lengths and int(lengths[0]) > body_limit:
                    return await reject(send, 413, 'Заявката надвишава допустимия размер.')

            body_deadline = asyncio.get_running_loop().time() + self.limits.body_total_seconds
            body_finished = False
            read_bytes = 0
            body_error = None
            response_started = False

            async def bounded_receive():
                nonlocal read_bytes, body_error, body_finished
                if not bounded_body or body_finished: return await receive()
                try:
                    remaining = body_deadline - asyncio.get_running_loop().time()
                    if remaining <= 0: raise TimeoutError()
                    message = await asyncio.wait_for(receive(), min(self.limits.body_idle_seconds, remaining))
                except TimeoutError:
                    body_error = 408
                    raise BodyReadTimedOut() from None
                if message['type'] == 'http.disconnect':
                    body_error = 400
                    raise BodyReadInterrupted()
                if message['type'] == 'http.request':
                    read_bytes += len(message.get('body', b''))
                    if read_bytes > body_limit:
                        body_error = 413
                        raise BodyLimitExceeded()
                    body_finished = not message.get('more_body', False)
                return message

            async def bounded_send(message):
                nonlocal response_started
                # The downstream framework can turn receive exceptions into a
                # generic 400/500. Suppress that response, then emit 413/408 once.
                if body_error is not None and not response_started: return
                if message['type'] == 'http.response.start': response_started = True
                await send(message)

            async def run():
                try:
                    await self.app(scope, bounded_receive, bounded_send)
                except (BodyLimitExceeded, BodyReadTimedOut, BodyReadInterrupted):
                    if response_started: raise
                if body_error is not None:
                    if response_started:
                        raise RuntimeError('body limit after response started')
                    await reject(send, body_error, {
                        413:'Надвишен размер на заявката.',
                        408:'Времето за получаване на файла изтече.',
                        400:'Качването е прекъснато.',
                    }[body_error])

            # A cancelled ASGI caller must NOT free shared capacity while a sync
            # endpoint / scanner thread is still running. Keep and drain the task
            # before re-raising cancellation. No lease TTL can over-admit work.
            task = asyncio.create_task(run())
            cancelled = False
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    if task.cancelled(): raise
                    cancelled = True
                except BaseException:
                    if cancelled: break
                    raise
            if cancelled:
                # Consume any inner exception and preserve caller cancellation.
                if not task.cancelled(): task.exception()
                raise asyncio.CancelledError()
            task.result()
        finally:
            for lease in reversed(leases): lease.close()


def install_synthetic_admission(portal, root: Path, *, prepare=False, capacity=2, upload_capacity=1):
    """Attach only to an explicitly generated temporary v8/v9 fixture app."""
    root = root.resolve()
    dbpath = Path(portal.engine.url.database or '').resolve()
    if (portal.PROD or portal.ENV != 'development' or portal.engine.dialect.name != 'sqlite'
            or not root.is_relative_to(Path(tempfile.gettempdir()).resolve())
            or not root.name.startswith(('FT8_SYNTHETIC_', 'FT9_SYNTHETIC_'))
            or not dbpath.is_relative_to(root) or not portal.STORAGE.is_relative_to(root)
            or not (root / 'SYNTHETIC_ONLY').is_file()):
        raise RuntimeError('HOLD: admission prototype requires an explicit temporary synthetic fixture')
    state = root / 'shared-admission'
    if prepare:
        state.mkdir(mode=0o700)
        total = DiskSlotPool.prepare(state / 'total', capacity)
        uploads = DiskSlotPool.prepare(state / 'uploads', upload_capacity)
    else:
        total = DiskSlotPool(state / 'total', capacity)
        uploads = DiskSlotPool(state / 'uploads', upload_capacity)
    portal.app = SharedPdfAdmission(portal.app, total, uploads)
    return total, uploads
