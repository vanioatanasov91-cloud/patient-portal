"""Conservative technical readiness preflight; NOT a GDPR certificate."""
from __future__ import annotations
import os
from pathlib import Path
from sqlalchemy import select
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / '.env')


def preflight():
    issues = []
    warnings = []
    env = os.getenv('PORTAL_ENV', 'development')
    if env != 'production':
        issues.append('PORTAL_ENV must be production for a public service')
    secret = os.getenv('PORTAL_SECRET', '')
    if len(secret) < 32 or secret.startswith(('CHANGE_THIS', 'REPLACE_')):
        issues.append('PORTAL_SECRET must be a random secret of 32+ characters')
    if os.getenv('PORTAL_COOKIE_SECURE', '') != '1':
        issues.append('PORTAL_COOKIE_SECURE=1 is required')
    hosts = [h.strip() for h in os.getenv('PORTAL_ALLOWED_HOSTS', '').split(',') if h.strip()]
    if not hosts or any(h in ('*', 'localhost', '127.0.0.1', 'testserver') or 'example.' in h for h in hosts):
        issues.append('Use only the real publicly authorized DNS host(s) in PORTAL_ALLOWED_HOSTS')
    if os.getenv('DATABASE_URL', '').startswith('sqlite'):
        warnings.append('SQLite: encrypted disk, single-instance operation and tested database backups are required')
    if not os.getenv('DATABASE_URL'):
        warnings.append('Default SQLite used; confirm DATABASE_URL is stable across restarts')
    env_file = BASE / '.env'
    if not env_file.is_file():
        issues.append('Missing .env with persisted configuration')
    if (BASE / '.demo_setup_done').exists():
        warnings.append('Demo-install marker detected; confirm demo credentials were replaced')
    try:
        import portal
        with portal.SessionLocal() as db:
            staff = db.scalars(select(portal.User).where(portal.User.role == 'staff', portal.User.active.is_(True))).all()
            if not staff:
                issues.append('There is no active staff account')
            for account in staff:
                if not account.mfa_secret_enc:
                    issues.append(f'Staff account ID {account.id}: TOTP MFA is not enrolled')
                if account.must_change_password:
                    issues.append(f'Staff account ID {account.id}: initial password must be changed')
                try:
                    if portal.ph.verify(account.password_hash, 'admin'):
                        issues.append(f'Staff account ID {account.id}: insecure demo password still present')
                except Exception:
                    pass
        if (BASE / 'private_data').resolve().is_relative_to((BASE / 'static').resolve()):
            issues.append('Private files appear inside public static directory')
    except Exception as exc:
        issues.append(f'Cannot inspect app/database: {type(exc).__name__}: {exc}')
    warnings += [
        'Manually verify HTTPS from an external client, reverse-proxy allowlist, firewall, DNS and HSTS',
        'Manually verify encrypted disks, OFFSITE backups and a timed restoration drill',
        'Perform independent penetration test, GDPR legal review/DPIA screening and approved retention policy',
        'Verify identities before giving patient credentials; assess patient MFA separately',
        'Do not copy production patient data into demo/test databases',
    ]
    return issues, warnings


if __name__ == '__main__':
    errors, notices = preflight()
    print('PATIENT PORTAL v1.6 — TECHNICAL PRE-FLIGHT (NOT CERTIFICATION)')
    for message in errors:
        print('FAIL:', message)
    for message in notices:
        print('REVIEW:', message)
    if errors:
        print('RESULT: NOT READY FOR PUBLIC DEPLOYMENT')
        raise SystemExit(1)
    print('RESULT: technical pre-flight passed; manual reviews are still REQUIRED')
