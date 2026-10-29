"""Local administration commands for patient portal test environment."""
import argparse
import getpass
import os
import secrets
import base64
from urllib.parse import quote
from sqlalchemy import select, func
from portal import SessionLocal, User, Report, LoginSession, AuthFailure, Audit, ph, encrypt_mfa_secret, verify_totp, decrypt_mfa_secret, PROD


def main():
    parser = argparse.ArgumentParser(description="Patient Portal administration")
    subs = parser.add_subparsers(dest="command", required=True)
    creator = subs.add_parser("create-admin", help="Create a staff account with a strong password")
    creator.add_argument("--username", required=True)
    creator.add_argument("--name", required=True)
    reset = subs.add_parser("reset-admin", help="Reset an EXISTING staff account password without deleting data")
    reset.add_argument("--username", default="admin")
    demo = subs.add_parser("demo-admin", help="LOCAL DEMO ONLY: set temporary admin/admin; password change required")
    demo.add_argument("--i-understand-this-is-insecure", action="store_true", required=True)
    enroll = subs.add_parser("enroll-mfa", help="Enroll staff TOTP authenticator locally")
    enroll.add_argument("--username", default="admin")
    args = parser.parse_args()

    if args.command == "enroll-mfa":
        with SessionLocal() as db:
            user = db.scalar(select(User).where(User.username == args.username, User.role == "staff"))
            if not user or not user.active:
                raise SystemExit("ERROR: active staff account not found")
            if user.mfa_secret_enc:
                raise SystemExit("ERROR: MFA already enrolled; no changes made")
            secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
            uri = ("otpauth://totp/" + quote("Patient Portal:" + user.username, safe="")
                   + "?secret=" + secret + "&issuer=Patient%20Portal&algorithm=SHA1&digits=6&period=30")
            print("Enter this setup key into an authenticator app (do NOT share it):")
            print(secret)
            print("Alternatively use this TOTP URI (keep confidential):")
            print(uri)
            code = getpass.getpass("Confirm 6-digit code from the app: ").strip()
            if not verify_totp(secret, code):
                raise SystemExit("ERROR: MFA confirmation failed; NOTHING saved")
            user.mfa_secret_enc = encrypt_mfa_secret(secret)
            db.query(LoginSession).filter(LoginSession.user_id == user.id).delete(synchronize_session=False)
            db.add(Audit(actor_id=None, action="staff_mfa_enrolled_local", target_id=user.id))
            db.commit()
            print("SUCCESS: MFA enabled; existing staff sessions revoked.")
        return

    if args.command == "create-admin":
        username = args.username.strip()
        if len(username) < 4 or len(username) > 80:
            raise SystemExit("Username length must be 4-80")
        with SessionLocal() as db:
            if db.scalar(select(User).where(User.username == username)):
                raise SystemExit("Username already exists")
            password = getpass.getpass("Strong admin password (16+ characters): ")
            if len(password) < 16:
                raise SystemExit("Admin password must be at least 16 characters")
            confirmation = getpass.getpass("Repeat password: ")
            if not secrets.compare_digest(password, confirmation):
                raise SystemExit("Passwords do not match")
            db.add(User(username=username, full_name=args.name.strip(),
                        password_hash=ph.hash(password), role="staff", must_change_password=False))
            db.commit()
            print("Admin account created. Never share these credentials.")

    if args.command == "reset-admin":
        username = args.username.strip()
        with SessionLocal() as db:
            user = db.scalar(select(User).where(User.username == username))
            if user is None or user.role != "staff":
                raise SystemExit("ERROR: Staff account not found. No data changed.")
            print(f"Resetting password of staff account: {username}")
            password = getpass.getpass("New strong password (16+ characters): ")
            if len(password) < 16 or len(password) > 128:
                raise SystemExit("ERROR: Password length must be 16-128. No data changed.")
            confirmation = getpass.getpass("Confirm new password: ")
            if not secrets.compare_digest(password, confirmation):
                raise SystemExit("ERROR: Passwords do not match. No data changed.")
            user.password_hash = ph.hash(password)
            user.active = True
            user.must_change_password = False
            db.query(LoginSession).filter(LoginSession.user_id == user.id).delete(synchronize_session=False)
            db.query(AuthFailure).delete(synchronize_session=False)
            db.add(Audit(actor_id=None, action="staff_password_reset_local", target_id=user.id))
            db.commit()
        print("SUCCESS: Admin password updated. All patients and reports preserved.")

    if args.command == "demo-admin":
        if os.environ.get("PORTAL_ENV", "development").lower() == "production":
            raise SystemExit("REFUSED: demo credentials cannot be enabled in production.")
        with SessionLocal() as db:
            # Never rewrite a live environment containing patient data.
            patients = db.scalar(select(func.count(User.id)).where(User.role == "patient")) or 0
            reports = db.scalar(select(func.count(Report.id))) or 0
            if patients or reports:
                raise SystemExit("REFUSED: existing patients/reports found. No changes made. Use a separate clean demo installation.")
            existing = db.scalar(select(User).where(User.username == "admin"))
            if existing and existing.role != "staff":
                raise SystemExit("REFUSED: username 'admin' belongs to a non-staff user.")
            if existing is None:
                existing = User(username="admin", full_name="Администратор (тест)",
                                password_hash="", role="staff", active=True)
                db.add(existing)
                db.flush()
            existing.password_hash = ph.hash("admin")
            existing.active = True
            existing.must_change_password = True
            # Old sessions must not survive a password reset.
            db.query(LoginSession).filter(LoginSession.user_id == existing.id).delete(synchronize_session=False)
            db.query(AuthFailure).delete(synchronize_session=False)
            db.commit()
        print("LOCAL DEMO account ready: username=admin, password=admin")
        print("You MUST set a stronger password on your FIRST login. NEVER use real patient data with this test setup.")


if __name__ == "__main__":
    main()
