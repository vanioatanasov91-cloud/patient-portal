"""Fixed localhost VERSION readiness check for the isolated synthetic pilot."""
from datetime import datetime, timedelta, timezone
import re
import socket
import time


def signature_is_fresh(reply, *, now=None):
    try:
        text = reply.decode('ascii')
        match = re.fullmatch(r'ClamAV [^/\r\n]+/[0-9]+/(.+)', text)
        if not match:
            return False
        stamp = datetime.strptime(match[1], '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc)
        age = (now or datetime.now(timezone.utc)) - stamp
        return timedelta(0) <= age <= timedelta(hours=48)
    except (ValueError, UnicodeError, OverflowError, TypeError):
        return False


def scanner_ready(port):
    """Bounded complete NUL-framed response; never include it in a UI/log."""
    try:
        deadline = time.monotonic() + 5
        reply = bytearray()
        with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
            connection.sendall(b'zVERSION\0')
            while len(reply) < 1024:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                connection.settimeout(min(2, remaining))
                block = connection.recv(min(256, 1024 - len(reply)))
                if not block:
                    break
                reply.extend(block)
                if b'\0' in block:
                    break
        return (reply.endswith(b'\0') and b'\0' not in reply[:-1]
                and signature_is_fresh(bytes(reply[:-1])))
    except (OSError, ValueError, OverflowError):
        return False


class PilotScannerCheck:
    def __init__(self, port):
        self.port = port

    def __call__(self):
        if not scanner_ready(self.port):
            from fastapi import HTTPException
            raise HTTPException(503, 'Антивирусната проверка е недостъпна или сигнатурите не са актуални. Опитайте по-късно.')
