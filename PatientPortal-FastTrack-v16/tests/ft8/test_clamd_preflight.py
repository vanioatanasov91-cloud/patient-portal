"""Mocked protocol preflight and candidate INSTREAM edge cases, no real daemon."""
from datetime import datetime, timezone
import importlib.util
import sys

from fixtures import candidate, ROOT
sys.path.insert(0, str(ROOT / 'tools'))
import clamd_preflight as probe
from fastapi import HTTPException


class Socket:
    def __init__(self, reply): self.reply = reply; self.sent = bytearray()
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def settimeout(self, timeout): assert 0 < timeout <= 5
    def sendall(self, data): self.sent.extend(data)
    def recv(self, size):
        # Exercise fragmentation of the framing marker and verdict.
        block, self.reply = self.reply[:min(3, size)], self.reply[min(3, size):]
        return block


def main():
    checks = 0
    def check(ok, label):
        nonlocal checks
        assert ok, label
        checks += 1
        print('PASS: ' + label)
    now = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
    real = probe.socket.create_connection
    try:
        for version, ready in [(b'ClamAV 1.4.0/123/Wed Oct 28 10:00:00 2026\0', True),
                               (b'ClamAV 1.4.0/123/Sun Oct 25 10:00:00 2026\0', False),
                               (b'ClamAV 1.4.0/123/Thu Oct 29 10:00:00 2026\0', False),
                               (b'invalid version\0', False)]:
            replies = iter([b'PONG\0', version, b'stream: OK\0', b'stream: Eicar-Test-Signature FOUND\0'])
            connections = []
            def connect(addr, timeout):
                connections.append((addr, timeout))
                return Socket(next(replies))
            probe.socket.create_connection = connect
            result = probe.probe(now=now)
            check(result['protocol_passed'] is ready, 'signature freshness / parsing fails closed: ' + str(ready))
            check(all(a == ('127.0.0.1',3310) for a, _ in connections), 'only loopback destination used')
            check(result['release_gate'] == 'HOLD / NO-GO' and result['production_approved'] is False,
                  'protocol pass never grants production approval')
        replies = iter([b'PONG\0', b'ClamAV 1.4/123/Wed Oct 28 10:00:00 2026\0'])
        probe.socket.create_connection = lambda *a, **k: Socket(next(replies))
        check(not probe.probe(now=now, signature_timezone='Invalid/SyntheticZone')['protocol_passed'], 'unknown signature timezone fails closed')
        replies = iter([b'PONG\0', b'ClamAV 1.4/123/Wed Oct 28 10:00:00 2026\0', b'stream: OK\0', b'stream: OK\0'])
        probe.socket.create_connection = lambda *a, **k: Socket(next(replies))
        check(not probe.probe(now=now)['protocol_passed'], 'EICAR missed by daemon blocks preflight')
        probe.socket.create_connection = lambda *a, **k: Socket(b'PONG')
        check(not probe.probe(now=now)['protocol_passed'], 'truncated probe reply fails closed')
        def offline(*a, **k): raise ConnectionRefusedError('SYNTHETIC')
        probe.socket.create_connection = offline
        check(not probe.probe(now=now)['protocol_passed'], 'daemon down fails closed')
    finally:
        probe.socket.create_connection = real
    with candidate() as (p, root):
        p.PDF_SCAN_MODE = 'clamd'
        path = root / 'synthetic.pdf'; path.write_bytes(b'%PDF-SYNTHETIC')
        real = p.socket.create_connection
        try:
            for reply in (b'stream: OK', b'stream: OK\n', b'stream: OK\0extra', b'X' * 1025 + b'\0', b'', b'stream: ERROR\0'):
                # Single-read variant makes trailing ambiguity observable.
                class OneRead(Socket):
                    def recv(self, size):
                        block, self.reply = self.reply[:size], self.reply[size:]
                        return block
                p.socket.create_connection = lambda *a, **k: OneRead(reply)
                try: p.scan_pdf_for_malware(path)
                except HTTPException as exc: check(exc.status_code == 503, 'malformed/incomplete upload verdict blocked')
                else: raise AssertionError('untrusted verdict accepted')
            p.socket.create_connection = lambda *a, **k: Socket(b'stream: OK\0')
            check(p.scan_pdf_for_malware(path) is True, 'fragmented complete OK accepted')
            real_time = p.time.monotonic
            ticks = iter([0, 31])
            p.time.monotonic = lambda: next(ticks)
            try:
                try: p.scan_pdf_for_malware(path)
                except HTTPException as exc: check(exc.status_code == 503, 'overall scanner deadline fails closed')
                else: raise AssertionError('deadline ignored')
            finally: p.time.monotonic = real_time
        finally: p.socket.create_connection = real
    print(f'PASS: FT8 CLAMD PREFLIGHT ({checks} checks). HOLD / NO-GO; MOCK SOCKETS ONLY.')


if __name__ == '__main__': main()
