"""Operator-only clamd protocol probe. No daemon installation or reconfiguration.

Not run against a real scanner by the suite. Only mocked sockets in tests.
Listener binding, ACL, logs and signature authenticity need independent evidence.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import json
import re
import socket
import struct
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Harmless industry AV test string, generated in memory; never written to disk.
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def exchange(port, command, payload=None):
    deadline = time.monotonic() + 10
    reply = bytearray()
    with socket.create_connection(('127.0.0.1', port), timeout=3) as conn:
        conn.settimeout(3)
        conn.sendall(b'z' + command + b'\0')
        if payload is not None:
            conn.sendall(struct.pack('!I', len(payload)) + payload + b'\0\0\0\0')
        while len(reply) < 1024:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('timeout')
            conn.settimeout(min(3, remaining))
            block = conn.recv(min(256, 1024 - len(reply)))
            if not block:
                break
            reply.extend(block)
            if b'\0' in block:
                break
    if not reply.endswith(b'\0') or b'\0' in reply[:-1]:
        raise ValueError('incomplete or ambiguous response')
    return bytes(reply[:-1])


def probe(port=3310, max_age_hours=48, *, now=None, signature_timezone="UTC"):
    if not 1 <= port <= 65535 or not 1 <= max_age_hours <= 168:
        raise ValueError('invalid port or maximum signature age')
    now = now or datetime.now(timezone.utc)
    checks = {'ping': False, 'signature_age': False, 'clean_control': False, 'eicar_rejected': False}
    # Do not return raw daemon replies, version strings, paths or signatures.
    try:
        checks['ping'] = exchange(port, b'PING') == b'PONG'
        version = exchange(port, b'VERSION').decode('ascii')
        match = re.fullmatch(r'ClamAV [^/\r\n]+/[0-9]+/(.+)', version)
        if match:
            stamp = datetime.strptime(match[1], '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc if signature_timezone == "UTC" else ZoneInfo(signature_timezone))
            checks['signature_age'] = timedelta(0) <= now - stamp <= timedelta(hours=max_age_hours)
        checks['clean_control'] = exchange(port, b'INSTREAM', b'SYNTHETIC CLEAN CONTROL') == b'stream: OK'
        answer = exchange(port, b'INSTREAM', EICAR)
        checks['eicar_rejected'] = bool(re.fullmatch(rb'stream: [^\x00\r\n]+ FOUND', answer))
    except (OSError, ValueError, UnicodeError, OverflowError, ZoneInfoNotFoundError):
        pass
    return {'mode': 'LOCAL OPERATOR PROBE', 'checks': checks,
            'protocol_passed': all(checks.values()), 'release_gate': 'HOLD / NO-GO',
            'production_approved': False,
            'signature_timestamp_timezone': signature_timezone,
            'manual_review_required': ['confirm the daemon timestamp timezone', 'listener lockdown and firewall', 'signature update source and authenticity',
                                       'daemon privileges and privacy of logs', 'resource limits and upload timeouts']}


def main():
    parser = argparse.ArgumentParser(description='Explicit operator-only localhost clamd probe; no installation')
    parser.add_argument('--confirm-local-operator-check', action='store_true')
    parser.add_argument('--port', type=int, default=3310)
    parser.add_argument('--max-age-hours', type=int, default=48)
    parser.add_argument('--signature-timezone', required=True, help='Operator-confirmed IANA timezone of daemon VERSION timestamp, e.g. UTC')
    args = parser.parse_args()
    if not args.confirm_local_operator_check:
        parser.error('No network probe by default. An operator must explicitly confirm this local-only check.')
    result = probe(args.port, args.max_age_hours, signature_timezone=args.signature_timezone)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['protocol_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
