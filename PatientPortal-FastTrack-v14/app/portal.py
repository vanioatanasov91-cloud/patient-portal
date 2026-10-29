"""Bulgarian patient portal - security-minded local MVP, NOT production approved."""
from __future__ import annotations

import hashlib
import base64
import struct
import time
from urllib.parse import quote
from cryptography.fernet import Fernet, InvalidToken
import io
import contextlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import sys
import threading
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from dotenv import load_dotenv
from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, create_engine, func, or_, select, exists, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from starlette.middleware.trustedhost import TrustedHostMiddleware
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")
ENV = os.environ.get("PORTAL_ENV", "development").strip().lower()
PROD = ENV == "production"
if ENV == "candidate" and not os.environ.get("PORTAL_CANDIDATE_INSTANCE"):
    raise RuntimeError("HOLD: use the isolated candidate entrypoint")
SECRET = os.environ.get("PORTAL_SECRET", "")
if PROD and (len(SECRET) < 32 or SECRET.startswith(("CHANGE_THIS", "REPLACE_"))):
    raise RuntimeError("Set a strong PORTAL_SECRET (32+ characters) for production")
if not SECRET:
    SECRET = secrets.token_urlsafe(48)  # development only, changes on restart
COOKIE_SECURE = os.environ.get("PORTAL_COOKIE_SECURE", "1" if PROD else "0") == "1"
if PROD and not COOKIE_SECURE:
    raise RuntimeError("Production cookies must be Secure over HTTPS")

# Fast Track 6: optional LOCAL clamd INSTREAM upload scanner.
# Development/offline synthetic work may use "off". Production MUST configure
# an independently operated scanner; lack of configuration is a startup HOLD.
PDF_SCAN_MODE = os.environ.get("PORTAL_PDF_SCAN_MODE", "off").strip().lower()
if PDF_SCAN_MODE not in ("off", "clamd"):
    raise RuntimeError("PORTAL_PDF_SCAN_MODE must be off or clamd")
if PROD and PDF_SCAN_MODE != "clamd":
    raise RuntimeError("HOLD: production PDF upload requires clamd scanning")
try:
    PDF_SCAN_PORT = int(os.environ.get("PORTAL_PDF_SCAN_PORT", "3310"))
except ValueError as exc:
    raise RuntimeError("Invalid PORTAL_PDF_SCAN_PORT") from exc
if not 1 <= PDF_SCAN_PORT <= 65535:
    raise RuntimeError("Invalid PORTAL_PDF_SCAN_PORT")

DB_URL = os.environ.get("DATABASE_URL", f"sqlite:///{BASE / 'private_data' / 'portal.sqlite3'}")
# FT10: a managed candidate DB must never be opened by the legacy entrypoint
# without its validated bootstrap. Inspect schema metadata read-only, before DDL
# or even creating storage directories. This is an accidental-bypass guard.
if DB_URL.startswith("sqlite:///"):
    _managed_path = Path(DB_URL.removeprefix("sqlite:///")).resolve()
    if _managed_path.is_file():
        with sqlite3.connect(_managed_path.as_uri() + "?mode=ro", uri=True) as _managed_db:
            if _managed_db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='candidate_schema'").fetchone():
                _managed_rows = _managed_db.execute("SELECT instance_id FROM candidate_schema").fetchall()
                if (ENV != "candidate" or _managed_rows != [(os.environ.get("PORTAL_CANDIDATE_INSTANCE"),)]):
                    raise RuntimeError("HOLD: managed candidate requires its validated entrypoint")
STORAGE = Path(os.environ.get("PRIVATE_STORAGE", str(BASE / "private_data" / "uploads"))).resolve()
STORAGE.mkdir(parents=True, exist_ok=True, mode=0o700)
if PROD and STORAGE.is_relative_to((BASE / "static").resolve()):
    raise RuntimeError("Private upload storage must not be under the public static directory")
if DB_URL.startswith("sqlite:///"):
    sqlite_db = Path(DB_URL.removeprefix("sqlite:///"))
    sqlite_db.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(160))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # staff | patient
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret_enc: Mapped[str | None] = mapped_column(String(255), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class LoginSession(Base):
    __tablename__ = "login_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(96))
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Nullable only for upgrading pre-v1.7 session rows. New sessions always set it.
    # A legacy row with NULL created_at is invalidated on its first use.
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user: Mapped[User] = relationship()

class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    uploaded_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    modality: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(120))
    exam_date: Mapped[date] = mapped_column(Date)
    stored_name: Mapped[str] = mapped_column(String(60), unique=True)
    original_name: Mapped[str] = mapped_column(String(180))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    file_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)

class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    details: Mapped[str | None] = mapped_column(String(250), nullable=True)

class AuthFailure(Base):
    __tablename__ = "auth_failures"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class CenterSettings(Base):
    __tablename__ = "center_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    center_name: Mapped[str] = mapped_column(String(140), default="Медицински център")
    phone: Mapped[str] = mapped_column(String(80), default="")
    email: Mapped[str] = mapped_column(String(160), default="")
    address: Mapped[str] = mapped_column(String(220), default="")
    website: Mapped[str] = mapped_column(String(200), default="")
    logo_filename: Mapped[str | None] = mapped_column(String(80), nullable=True)


Base.metadata.create_all(engine)


def migrate_v14_schema() -> None:
    """Idempotent SQLite upgrade. Old reports stay published, not draft.

    Production systems require a reviewed versioned migration; intentionally
    refuse automatic cross-DB DDL changes rather than guessing a dialect.
    """
    columns_sessions = {col["name"] for col in inspect(engine).get_columns("login_sessions")}
    columns_users = {col["name"] for col in inspect(engine).get_columns("users")}
    columns_reports = {col["name"] for col in inspect(engine).get_columns("reports")}
    columns_audit = {col["name"] for col in inspect(engine).get_columns("audit")}
    missing = ("published_at" not in columns_reports or "details" not in columns_audit
               or "file_sha256" not in columns_reports or "mfa_secret_enc" not in columns_users
               or "mfa_verified" not in columns_sessions)
    if missing and engine.dialect.name != "sqlite":
        raise RuntimeError("v1.4 requires an approved database migration outside SQLite")
    with engine.begin() as connection:
        if "mfa_verified" not in columns_sessions:
            connection.execute(text("ALTER TABLE login_sessions ADD COLUMN mfa_verified BOOLEAN DEFAULT 0"))
        if "mfa_secret_enc" not in columns_users:
            connection.execute(text("ALTER TABLE users ADD COLUMN mfa_secret_enc VARCHAR(255)"))
        if "published_at" not in columns_reports:
            connection.execute(text("ALTER TABLE reports ADD COLUMN published_at DATETIME"))
            # Previously uploaded non-revoked reports were already visible.
            # Revoked old reports retain their former published timestamp too.
            connection.execute(text("UPDATE reports SET published_at = uploaded_at"))
        if "details" not in columns_audit:
            connection.execute(text("ALTER TABLE audit ADD COLUMN details VARCHAR(250)"))
        if "file_sha256" not in columns_reports:
            connection.execute(text("ALTER TABLE reports ADD COLUMN file_sha256 VARCHAR(64)"))


migrate_v14_schema()


def migrate_v17_session_schema() -> None:
    """Add one session-only SQLite column; preserve users and medical reports.

    Existing sessions have NULL created_at and must reauthenticate. There is no
    guessed creation time and no table rewrite. Fail closed for other dialects.
    """
    columns = {col["name"] for col in inspect(engine).get_columns("login_sessions")}
    if "created_at" in columns:
        return
    if engine.dialect.name != "sqlite":
        raise RuntimeError("Session absolute-timeout migration must be reviewed for non-SQLite DBs")
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE login_sessions ADD COLUMN created_at DATETIME"))


migrate_v17_session_schema()
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
signer = URLSafeTimedSerializer(SECRET, salt="patient-portal-login-csrf")

# Staff MFA secrets are encrypted at rest with a key derived from the stable
# PORTAL_SECRET. The operator MUST preserve that secret when restoring backups.
_mfa_key = base64.urlsafe_b64encode(hashlib.sha256(b"patient-portal-mfa-v16:" + SECRET.encode()).digest())
_mfa_cipher = Fernet(_mfa_key)


def encrypt_mfa_secret(secret: str) -> str:
    return _mfa_cipher.encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_mfa_secret(ciphertext: str) -> str:
    try:
        return _mfa_cipher.decrypt(ciphertext.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError) as ex:
        raise RuntimeError("MFA key mismatch: restore original PORTAL_SECRET") from ex


def totp_now(secret: str, tick: int | None = None) -> str:
    """RFC 6238, 30-second TOTP with SHA1 for standard authenticator apps."""
    counter = int(time.time() if tick is None else tick) // 30
    key = base64.b32decode(secret.upper(), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1000000:06d}"


def verify_totp(secret: str, code: str, *, tick: int | None = None) -> bool:
    if not re.fullmatch(r"[0-9]{6}", code):
        return False
    when = int(time.time() if tick is None else tick)
    return any(hmac.compare_digest(totp_now(secret, when + delta), code)
               for delta in (-30, 0, 30))

if PROD:
    if "*" in os.environ.get("PORTAL_ALLOWED_HOSTS", ""):
        raise RuntimeError("Production must specify concrete PORTAL_ALLOWED_HOSTS")
    if os.environ.get("PORTAL_ALLOWED_HOSTS", "").strip() in ("", "localhost", "127.0.0.1"):
        raise RuntimeError("Production requires public domain in PORTAL_ALLOWED_HOSTS")

app = FastAPI(title="Пациентски портал", docs_url=None, redoc_url=None, openapi_url=None)
hosts = [x.strip() for x in os.environ.get("PORTAL_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver").split(",") if x.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))

# Hide sensitive responses from caches and indexers (including errors).
@app.middleware("http")
async def security_headers(request: Request, call_next):
    # A reverse proxy must supply trusted scheme information (Uvicorn's
    # --forwarded-allow-ips=127.0.0.1); never trust client-supplied XFP here.
    if PROD and request.url.scheme != "https":
        return Response("HTTPS is required", status_code=400,
                        headers={"Cache-Control": "no-store"})
    response = await call_next(request)
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
    if PROD:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def db_session() -> Generator[Session, None, None]:
    with SessionLocal() as db:
        yield db


def now() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(d: datetime) -> datetime:
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)


def log(db: Session, actor: int | None, action: str, target: int | None = None,
        *, details: str | None = None) -> None:
    # Never log plaintext credentials, raw identifiers or medical PDF bodies.
    db.add(Audit(actor_id=actor, action=action, target_id=target,
                 details=details[:250] if details else None))


def center_config(db: Session | None = None) -> CenterSettings:
    # Configuration remains in the same existing SQLite database.
    if db is None:
        with SessionLocal() as local_db:
            found = local_db.get(CenterSettings, 1)
            return found or CenterSettings(id=1, center_name="Медицински център", phone="", email="", address="", website="")
    return db.get(CenterSettings, 1) or CenterSettings(id=1, center_name="Медицински център", phone="", email="", address="", website="")


def page(request: Request, name: str, *, user: User | None = None, csrf: str = "", status_code: int = 200, **context):
    return templates.TemplateResponse(request, name, {"user": user, "csrf": csrf,
            "center": center_config(), "path": request.url.path,
            "pdf_av_policy_enabled": pdf_av_policy is not None, **context}, status_code=status_code)


SESSION_ABSOLUTE_HOURS = 8


def make_session(db: Session, user: User, *, mfa_verified: bool = False) -> tuple[str, str]:
    raw = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(48)
    issued_at = now()
    idle_mins = 15 if user.role == "staff" else 20
    db.add(LoginSession(token_hash=hashlib.sha256(raw.encode()).hexdigest(), user_id=user.id,
                        csrf_token=csrf, mfa_verified=mfa_verified, created_at=issued_at,
                        expires_at=issued_at + timedelta(minutes=idle_mins)))
    db.commit()
    return raw, csrf


def set_auth_cookie(response, raw: str) -> None:
    response.set_cookie("portal_session", raw, httponly=True, secure=COOKIE_SECURE, samesite="lax", path="/", max_age=8 * 3600)


def current_session(request: Request, db: Session) -> LoginSession | None:
    raw = request.cookies.get("portal_session", "")
    if not raw or len(raw) > 200:
        return None
    session = db.scalar(select(LoginSession).where(LoginSession.token_hash == hashlib.sha256(raw.encode()).hexdigest()))
    if not session:
        return None
    checked_at = now()
    # An old session has no trustworthy issue time. Expire it, not guess its age.
    absolute_end = (as_utc(session.created_at) + timedelta(hours=SESSION_ABSOLUTE_HOURS)
                    if session.created_at is not None else None)
    if (absolute_end is None or checked_at >= absolute_end or
        as_utc(session.expires_at) <= checked_at or not session.user.active or
        (session.user.role == "staff" and PROD and not session.mfa_verified) or
        (session.user.role == "staff" and session.user.mfa_secret_enc and not session.mfa_verified)):
        db.delete(session)
        db.commit()
        return None
    # Sliding idle timer, independently bounded by the immutable issue time.
    # Staff: 15 minutes; patient: 20 minutes; absolute: 8 hours, server-enforced.
    idle_end = checked_at + timedelta(minutes=15 if session.user.role == "staff" else 20)
    session.expires_at = min(idle_end, absolute_end)
    db.commit()
    return session


def require_auth(request: Request, db: Session, *, role: str | None = None) -> LoginSession:
    ses = current_session(request, db)
    if not ses:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    if ses.user.role == "staff" and ses.user.must_change_password and request.url.path not in ("/change-password", "/logout"):
        raise HTTPException(status_code=303, headers={"Location": "/change-password"})
    if role and ses.user.role != role:
        raise HTTPException(status_code=403, detail="Нямате право на достъп.")
    return ses


def check_csrf(ses: LoginSession, given: str) -> None:
    if not given or not hmac.compare_digest(ses.csrf_token, given):
        raise HTTPException(status_code=403, detail="Невалиден защитен код на формуляра.")


def client_fingerprint(request: Request, username: str) -> str:
    # A keyed fingerprint keeps raw IPs out of the failed-login table.
    ip = request.client.host if request.client else "unknown"
    return hmac.new(SECRET.encode(), f"{ip}|{username.casefold()}".encode(), hashlib.sha256).hexdigest()


def login_template(request: Request, *, error: str | None = None, status_code: int = 200):
    raw = secrets.token_urlsafe(32)
    signed = signer.dumps(raw)
    res = page(request, "login.html", login_token=signed, error=error, status_code=status_code)
    res.set_cookie("login_csrf", signed, httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=1200, path="/")
    return res


@app.get("/", include_in_schema=False)
def root(request: Request, db: Session = Depends(db_session)):
    ses = current_session(request, db)
    return RedirectResponse("/dashboard" if ses else "/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, db: Session = Depends(db_session)):
    if current_session(request, db):
        return RedirectResponse("/dashboard", status_code=303)
    return login_template(request)


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...),
          login_token: str = Form(""), mfa_code: str = Form(""), db: Session = Depends(db_session)):
    cookie = request.cookies.get("login_csrf", "")
    if not cookie or not login_token or not hmac.compare_digest(cookie, login_token):
        raise HTTPException(403, "Невалиден формуляр.")
    try:
        signer.loads(login_token, max_age=1200)
    except (BadSignature, SignatureExpired):
        raise HTTPException(403, "Изтекъл формуляр.")
    username = username.strip()[:80]
    fingerprint = client_fingerprint(request, username)
    since = now() - timedelta(minutes=15)
    db.query(AuthFailure).filter(AuthFailure.occurred_at < now() - timedelta(days=1)).delete(synchronize_session=False)
    ip_fingerprint = client_fingerprint(request, "*")
    count = db.scalar(select(func.count(AuthFailure.id)).where(
        AuthFailure.fingerprint == fingerprint, AuthFailure.occurred_at > since)) or 0
    ip_count = db.scalar(select(func.count(AuthFailure.id)).where(
        AuthFailure.fingerprint == ip_fingerprint, AuthFailure.occurred_at > since)) or 0
    if count >= 8 or ip_count >= 40:
        return login_template(request, error="Твърде много неуспешни опити. Опитайте след 15 минути.", status_code=429)
    user = db.scalar(select(User).where(User.username == username))
    ok = False
    if user and user.active:
        try:
            ok = ph.verify(user.password_hash, password)
        except (VerificationError, VerifyMismatchError):
            pass
    else:
        # Mitigate gross account enumeration through timing differences.
        try:
            ph.verify(DUMMY_HASH, password)
        except (VerificationError, VerifyMismatchError):
            pass
    # Staff cannot authenticate without an enrolled second factor in production.
    # Existing development admins continue working until MFA enrollment.
    if ok and user.role == "staff":
        if PROD and (not user.mfa_secret_enc or user.must_change_password):
            ok = False
        elif user.mfa_secret_enc:
            secret = decrypt_mfa_secret(user.mfa_secret_enc)
            ok = verify_totp(secret, mfa_code.strip())
    if not ok:
        db.add(AuthFailure(fingerprint=fingerprint))
        db.add(AuthFailure(fingerprint=ip_fingerprint))
        log(db, None, "login_failed")
        db.commit()
        return login_template(request, error="Невалидно потребителско име или парола.", status_code=401)
    db.query(AuthFailure).filter(AuthFailure.fingerprint == fingerprint).delete()
    raw, _ = make_session(db, user, mfa_verified=bool(user.role == "staff" and user.mfa_secret_enc))
    log(db, user.id, "login_success")
    db.commit()
    res = RedirectResponse("/change-password" if user.role == "staff" and user.must_change_password else "/dashboard", status_code=303)
    set_auth_cookie(res, raw)
    res.delete_cookie("login_csrf", path="/")
    return res

# Precomputed dummy hash for unknown accounts, never accepted as a login credential.
DUMMY_HASH = ph.hash(secrets.token_urlsafe(24))


@app.post("/logout")
def logout(request: Request, csrf: str = Form(""), db: Session = Depends(db_session)):
    ses = require_auth(request, db)
    check_csrf(ses, csrf)
    log(db, ses.user_id, "logout")
    db.delete(ses)
    db.commit()
    res = RedirectResponse("/login", status_code=303)
    res.delete_cookie("portal_session", path="/")
    return res


PAGE_SIZE = 25


def normalize_page(value: int) -> int:
    return min(max(1, value), 100000)


def escaped_search(value: str) -> str:
    # Interpret search terms literally, not as SQL LIKE wildcards.
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@app.get("/dashboard")
def dashboard(request: Request, q: str = "", status: str = "all", documents: str = "all",
              sort: str = "newest", page_num: int = 1, db: Session = Depends(db_session)):
    ses = require_auth(request, db)
    if ses.user.role == "patient":
        docs = db.scalars(select(Report).where(Report.patient_id == ses.user_id,
                       Report.revoked_at.is_(None), Report.published_at.is_not(None)).order_by(Report.exam_date.desc(), Report.id.desc())).all()
        return page(request, "patient.html", user=ses.user, csrf=ses.csrf_token, docs=docs)

    q = q.strip()[:80]
    status = status if status in ("all", "active", "inactive") else "all"
    documents = documents if documents in ("all", "with", "without") else "all"
    query = select(User).where(User.role == "patient")
    if q:
        pattern = f"%{escaped_search(q)}%"
        query = query.where(or_(User.full_name.ilike(pattern, escape="\\"),
                                User.username.ilike(pattern, escape="\\")))
    if status != "all":
        query = query.where(User.active.is_(status == "active"))
    active_doc_exists = exists(select(Report.id).where(
        Report.patient_id == User.id, Report.revoked_at.is_(None),
        Report.published_at.is_not(None)))
    if documents == "with":
        query = query.where(active_doc_exists)
    elif documents == "without":
        query = query.where(~active_doc_exists)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    last_page = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page_num = min(normalize_page(page_num), last_page)
    sort = sort if sort in ("newest", "oldest", "name_asc", "name_desc", "latest_exam") else "newest"
    latest_exam = select(func.max(Report.exam_date)).where(Report.patient_id == User.id).correlate(User).scalar_subquery()
    order = {
        "newest": (User.id.desc(),), "oldest": (User.id.asc(),),
        "name_asc": (User.full_name.asc(), User.id.asc()),
        "name_desc": (User.full_name.desc(), User.id.desc()),
        "latest_exam": (latest_exam.desc().nulls_last(), User.id.desc()),
    }[sort]
    patients = db.scalars(query.order_by(*order).limit(PAGE_SIZE)
                          .offset((page_num - 1) * PAGE_SIZE)).all()
    stats = {
        "patients": db.scalar(select(func.count(User.id)).where(User.role == "patient")) or 0,
        "active_patients": db.scalar(select(func.count(User.id)).where(User.role == "patient", User.active.is_(True))) or 0,
        "docs": db.scalar(select(func.count(Report.id)).where(Report.revoked_at.is_(None), Report.published_at.is_not(None))) or 0,
        "drafts": db.scalar(select(func.count(Report.id)).where(Report.revoked_at.is_(None), Report.published_at.is_(None))) or 0,
        "uploaded_today": db.scalar(select(func.count(Report.id)).where(
            Report.uploaded_at >= now() - timedelta(hours=24))) or 0,
    }
    latest_rows = db.execute(select(Report, User).join(User, Report.patient_id == User.id)
                             .order_by(Report.uploaded_at.desc(), Report.id.desc()).limit(6)).all()
    return page(request, "staff.html", user=ses.user, csrf=ses.csrf_token,
                patients=patients, stats=stats, q=q, status=status, documents=documents,
                page_num=page_num, last_page=last_page, total=total, latest_rows=latest_rows, sort=sort)


@app.get("/reports")
def staff_reports(request: Request, q: str = "", modality: str = "all", status: str = "all",
                  page_num: int = 1, db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    q = q.strip()[:80]
    modality = modality if modality in MODALITIES else "all"
    status = status if status in ("all", "active", "draft", "revoked") else "all"
    query = select(Report, User).join(User, User.id == Report.patient_id).where(User.role == "patient")
    if q:
        pattern = f"%{escaped_search(q)}%"
        query = query.where(or_(User.full_name.ilike(pattern, escape="\\"),
                                User.username.ilike(pattern, escape="\\"),
                                Report.title.ilike(pattern, escape="\\")))
    if modality != "all":
        query = query.where(Report.modality == modality)
    if status == "active":
        query = query.where(Report.revoked_at.is_(None), Report.published_at.is_not(None))
    elif status == "draft":
        query = query.where(Report.revoked_at.is_(None), Report.published_at.is_(None))
    elif status == "revoked":
        query = query.where(Report.revoked_at.is_not(None))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    last_page = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page_num = min(normalize_page(page_num), last_page)
    rows = db.execute(query.order_by(Report.uploaded_at.desc(), Report.id.desc())
                      .limit(PAGE_SIZE).offset((page_num - 1) * PAGE_SIZE)).all()
    return page(request, "reports.html", user=ses.user, csrf=ses.csrf_token,
                rows=rows, q=q, modality=modality, status=status,
                modalities=MODALITIES, total=total, page_num=page_num, last_page=last_page)


@app.get("/settings")
def settings_page(request: Request, db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    return page(request, "settings.html", user=ses.user, csrf=ses.csrf_token,
                settings=center_config(db))


@app.post("/settings")
def save_settings(request: Request, csrf: str = Form(""), center_name: str = Form(""),
                  phone: str = Form(""), email: str = Form(""),
                  website: str = Form(""), address: str = Form(""),
                  db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    center_name, phone, email = center_name.strip(), phone.strip(), email.strip()
    website, address = website.strip(), address.strip()
    if not (2 <= len(center_name) <= 140 and len(phone) <= 80 and len(email) <= 160
            and len(website) <= 200 and len(address) <= 220):
        raise HTTPException(422, "Невалидни или прекалено дълги данни за центъра.")
    if any(ord(c) < 32 for val in (center_name, phone, email, website, address) for c in val):
        raise HTTPException(422, "Недопустими символи в настройките.")
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(422, "Въведете валиден имейл адрес.")
    if website and not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[^\s]*)?", website):
        raise HTTPException(422, "Адресът на сайта трябва да започва с https://")
    settings = db.get(CenterSettings, 1)
    if not settings:
        settings = CenterSettings(id=1)
        db.add(settings)
    settings.center_name, settings.phone, settings.email = center_name, phone, email
    settings.website, settings.address = website, address
    log(db, ses.user_id, "center_settings_updated", details="Променени данни на медицинския център")
    db.commit()
    return RedirectResponse("/settings?saved=1", status_code=303)


@app.post("/settings/logo")
def upload_logo(request: Request, logo: UploadFile = File(...), csrf: str = Form(""),
                db: Session = Depends(db_session)):
    from PIL import Image, UnidentifiedImageError
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    raw = logo.file.read(2 * 1024 * 1024 + 1)
    logo.file.close()
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(413, "Максималният размер на логото е 2 MB.")
    try:
        with Image.open(io.BytesIO(raw)) as img:
            if img.format not in ("PNG", "JPEG") or img.width > 2400 or img.height > 2400:
                raise ValueError("invalid size/format")
            # Re-encode the image, stripping metadata and polyglot content.
            cleaned = Image.new("RGB", img.size, "white")
            if img.mode in ("RGBA", "LA", "P"):
                png = img.convert("RGBA")
                cleaned.paste(png, mask=png.getchannel("A"))
            else:
                cleaned.paste(img.convert("RGB"))
            buffer = io.BytesIO()
            cleaned.save(buffer, format="PNG", optimize=True)
    except (UnidentifiedImageError, ValueError, OSError, SyntaxError):
        raise HTTPException(422, "Изберете валидна PNG/JPG снимка с размер до 2400×2400 пиксела.")
    filename = f"brand_{secrets.token_hex(12)}.png"
    folder = STORAGE / "branding"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    new_path = folder / filename
    new_path.write_bytes(buffer.getvalue())
    new_path.chmod(0o600)
    settings = db.get(CenterSettings, 1)
    if settings is None:
        settings = CenterSettings(id=1, center_name="Медицински център")
        db.add(settings)
    old = settings.logo_filename
    settings.logo_filename = filename
    log(db, ses.user_id, "center_logo_updated")
    try:
        db.commit()
    except Exception:
        new_path.unlink(missing_ok=True)
        raise
    if old and re.fullmatch(r"brand_[a-f0-9]{24}\.png", old):
        (folder / old).unlink(missing_ok=True)
    return RedirectResponse("/settings?saved=1", status_code=303)


@app.get("/center-logo")
def center_logo(db: Session = Depends(db_session)):
    config = center_config(db)
    if not config.logo_filename or not re.fullmatch(r"brand_[a-f0-9]{24}\.png", config.logo_filename):
        raise HTTPException(404)
    logo_path = STORAGE / "branding" / config.logo_filename
    if not logo_path.is_file():
        raise HTTPException(404)
    return FileResponse(logo_path, media_type="image/png", headers={"X-Content-Type-Options": "nosniff"})


@app.get("/patients/new")
def new_patient(request: Request, db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    return page(request, "new_patient.html", user=ses.user, csrf=ses.csrf_token)


def valid_patient_identifier(value: str, kind: str) -> bool:
    """Validate Bulgarian EGN/LNCh (10 decimal digits with appropriate checksum)."""
    if not re.fullmatch(r"[0-9]{10}", value):
        return False
    digits = [int(ch) for ch in value]
    if kind == "EGN":
        yy, mm, dd = digits[0]*10 + digits[1], digits[2]*10 + digits[3], digits[4]*10 + digits[5]
        if 1 <= mm <= 12:
            year = 1900 + yy
        elif 21 <= mm <= 32:
            year, mm = 1800 + yy, mm - 20
        elif 41 <= mm <= 52:
            year, mm = 2000 + yy, mm - 40
        else:
            return False
        try:
            date(year, mm, dd)
        except ValueError:
            return False
        checksum = sum(a*b for a,b in zip(digits[:9], (2,4,8,5,10,9,7,3,6))) % 11
        return digits[9] == (0 if checksum == 10 else checksum)
    if kind == "LNCH":
        checksum = sum(a*b for a,b in zip(digits[:9], (21,19,17,13,11,9,7,3,1))) % 10
        return digits[9] == checksum
    return False


def credentials_pdf(*, full_name: str, username: str, password: str) -> bytes:
    """Generate credential PDF only in memory; never save a plaintext password to disk."""
    from reportlab.lib.colors import HexColor
    from reportlab.lib.pagesizes import A5
    # Use a local OS font for Cyrillic. Fonts are NOT distributed with the project.
    options = [
        Path(os.environ.get("PORTAL_PDF_FONT", "")) if os.environ.get("PORTAL_PDF_FONT") else None,
        Path('C:/Windows/Fonts/arial.ttf'), Path('C:/Windows/Fonts/segoeui.ttf'),
        Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),
        Path('/usr/share/fonts/truetype/clear-sans/ClearSans-Regular.ttf'),
    ]
    font = next((v for v in options if v and v.is_file()), None)
    if not font:
        raise HTTPException(503, "Няма наличен шрифт за генериране на PDF. Проверете системните шрифтове.")
    pdfmetrics.registerFont(TTFont('PortalBg', str(font)))
    output = io.BytesIO()
    doc = canvas.Canvas(output, pagesize=A5, pageCompression=1)
    width, height = A5
    doc.setFillColor(HexColor('#164b85'))
    doc.rect(0, height-98, width, 98, fill=1, stroke=0)
    doc.setFillColorRGB(1, 1, 1)
    doc.setFont('PortalBg', 17)
    config = center_config()
    brand_name = config.center_name or "Медицински център"
    has_logo = bool(config.logo_filename)
    brand_width = width - (120 if has_logo else 65)
    brand_size = min(17, max(8, 17 * brand_width/max(1, pdfmetrics.stringWidth(brand_name, 'PortalBg', 17))))
    doc.setFont('PortalBg', brand_size)
    doc.drawString(30, height-45, brand_name)
    if has_logo and re.fullmatch(r'brand_[a-f0-9]{24}\.png', config.logo_filename):
        logo_path = STORAGE / 'branding' / config.logo_filename
        if logo_path.is_file():
            try:
                from reportlab.lib.utils import ImageReader
                doc.setFillColorRGB(1, 1, 1)
                doc.roundRect(width-96, height-84, 66, 58, 7, fill=1, stroke=0)
                doc.drawImage(ImageReader(str(logo_path)), width-92, height-80,
                              width=58, height=50, preserveAspectRatio=True, anchor='c', mask='auto')
            except (OSError, ValueError):
                pass
    doc.setFillColorRGB(1, 1, 1)
    doc.setFont('PortalBg', 9)
    doc.drawString(30, height-70, 'Пациентски портал · Данни за достъп')
    doc.setFillColor(HexColor('#18314b'))
    y = height - 130
    for caption, val in [('Пациент', full_name), ('Потребителско име (ЕГН/ЛНЧ)', username), ('Парола за достъп', password)]:
        doc.setFont('PortalBg', 9)
        doc.setFillColor(HexColor('#607086'))
        doc.drawString(30, y, caption)
        y -= 25
        doc.setFont('PortalBg', 12)
        doc.setFillColor(HexColor('#173558'))
        # Long names may extend too far; fit dynamically without truncating.
        fitted = min(12, 355 / max(1, pdfmetrics.stringWidth(val, 'PortalBg', 12)) * 12)
        doc.setFont('PortalBg', max(7, fitted))
        doc.drawString(30, y, val)
        y -= 46
    doc.setStrokeColor(HexColor('#dce5ef'))
    doc.line(30, y+11, width-30, y+11)
    doc.setFont('PortalBg', 9)
    doc.setFillColor(HexColor('#18314b'))
    for line in (
        'Влезте в адреса, посочен от медицинския център.',
        'Използвайте тази парола за следващите влизания.',
        'Пазете този лист от други лица.',
        'При изгубена парола поискайте нова от служител.',
    ):
        y -= 21
        doc.drawString(30, y, line)
    # Contact details on the access slip; credentials themselves are never persisted.
    doc.setFont('PortalBg', 8)
    doc.setFillColor(HexColor('#566c80'))
    for value in (config.phone, config.email, config.website, config.address):
        if value and y > 88:
            y -= 16
            fit = min(8, 8 * (width - 65) / max(1, pdfmetrics.stringWidth(value, 'PortalBg', 8)))
            doc.setFont('PortalBg', max(6, fit))
            doc.drawString(30, y, value)
    doc.setFont('PortalBg', 8)
    doc.setFillColor(HexColor('#9b6320'))
    doc.drawString(30, 40, 'ТЕСТОВА ВЕРСИЯ — не използвайте с реални пациенти')
    doc.setTitle('Данни за достъп до пациентски портал')
    doc.setAuthor('Пациентски портал')
    doc.showPage()
    doc.save()
    return output.getvalue()


@app.post("/patients/new")
def create_patient(request: Request, full_name: str = Form(...), identifier: str = Form(""),
                   identifier_type: str = Form("EGN"), csrf: str = Form(""),
                   db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    full_name = full_name.strip()
    identifier = identifier.strip()
    def fail(message: str):
        return page(request, "new_patient.html", user=ses.user, csrf=ses.csrf_token,
                    error=message, full_name=full_name, identifier=identifier,
                    identifier_type=identifier_type, status_code=422)
    if not 2 <= len(full_name) <= 160:
        return fail("Въведете име между 2 и 160 символа.")
    if identifier_type not in ("EGN", "LNCH") or not valid_patient_identifier(identifier, identifier_type):
        return fail("Невалидно ЕГН/ЛНЧ. Проверете 10-те цифри, типа на документа и контролната цифра.")
    # Usernames must remain globally unique, including staff accounts and old profiles.
    if db.scalar(select(User.id).where(User.username == identifier)) is not None:
        return fail("Вече съществува профил с този ЕГН/ЛНЧ. Отворете го от списъка с пациенти.")
    password = secrets.token_urlsafe(18)
    patient = User(username=identifier, full_name=full_name, password_hash=ph.hash(password),
                   role="patient", must_change_password=False)
    db.add(patient)
    try:
        db.flush()
        log(db, ses.user_id, "patient_created", patient.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        return fail("Вече съществува профил с този ЕГН/ЛНЧ.")
    return page(request, "credentials.html", user=ses.user, csrf=ses.csrf_token,
                patient=patient, username=identifier, password=password, operation="Създаден пациент")


@app.post("/patients/{patient_id}/credentials-pdf")
def export_credentials(request: Request, patient_id: int, password: str = Form(""),
                       disposition: str = Form("attachment"), csrf: str = Form(""),
                       db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    patient = get_patient(db, patient_id)
    if not password or len(password) > 128 or disposition not in ("attachment", "inline"):
        raise HTTPException(400, "Невалидна заявка за PDF.")
    # Allow export only when the staff provides the current password from the
    # newly-created credential screen. The server never stores it in plaintext.
    try:
        if not ph.verify(patient.password_hash, password):
            raise HTTPException(403, "Данните вече не са валидни.")
    except (VerificationError, VerifyMismatchError):
        raise HTTPException(403, "Данните вече не са валидни.")
    data = credentials_pdf(full_name=patient.full_name, username=patient.username, password=password)
    log(db, ses.user_id, "credentials_pdf_exported", patient.id)
    db.commit()
    return Response(content=data, media_type="application/pdf", headers={
        "Content-Disposition": f'{disposition}; filename="patient_access_{patient.id}.pdf"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
    })


def get_patient(db: Session, patient_id: int) -> User:
    patient = db.get(User, patient_id)
    if not patient or patient.role != "patient":
        raise HTTPException(404, "Пациентът не е намерен.")
    return patient


@app.get("/patients/{patient_id}")
def patient_detail(request: Request, patient_id: int, db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    patient = get_patient(db, patient_id)
    docs = db.scalars(select(Report).where(Report.patient_id == patient.id).order_by(Report.id.desc())).all()
    return page(request, "detail.html", user=ses.user, csrf=ses.csrf_token, patient=patient, docs=docs)


@app.get("/patients/{patient_id}/edit")
def edit_patient_form(request: Request, patient_id: int, db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    patient = get_patient(db, patient_id)
    identifier_type = "EGN" if valid_patient_identifier(patient.username, "EGN") else "LNCH"
    return page(request, "edit_patient.html", user=ses.user, csrf=ses.csrf_token,
                patient=patient, full_name=patient.full_name, identifier=patient.username,
                identifier_type=identifier_type)


@app.post("/patients/{patient_id}/edit")
def edit_patient(request: Request, patient_id: int, full_name: str = Form(...),
                 identifier: str = Form(...), identifier_type: str = Form("EGN"),
                 confirm_identifier: str = Form(""), csrf: str = Form(""),
                 db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    patient = get_patient(db, patient_id)
    full_name, identifier = full_name.strip(), identifier.strip()
    def fail(msg: str):
        return page(request, "edit_patient.html", user=ses.user, csrf=ses.csrf_token,
                    patient=patient, full_name=full_name, identifier=identifier,
                    identifier_type=identifier_type, error=msg, status_code=422)
    if not 2 <= len(full_name) <= 160:
        return fail("Името трябва да е между 2 и 160 символа.")
    changed_id = identifier != patient.username
    if changed_id:
        if not valid_patient_identifier(identifier, identifier_type):
            return fail("Невалидно ЕГН/ЛНЧ. Проверете типа и контролната цифра.")
        if confirm_identifier != "yes":
            return fail("Потвърдете промяната на ЕГН/ЛНЧ, преди да запишете.")
        existing = db.scalar(select(User.id).where(User.username == identifier))
        if existing is not None:
            return fail("Това ЕГН/ЛНЧ вече е регистрирано.")
    changed_name = full_name != patient.full_name
    if not changed_id and not changed_name:
        return RedirectResponse(f"/patients/{patient.id}", status_code=303)
    patient.full_name = full_name
    if changed_id:
        patient.username = identifier
        # Existing patient sessions must not survive a changed login identifier.
        db.query(LoginSession).filter(LoginSession.user_id == patient.id).delete()
    fields = ", ".join(x for condition, x in ((changed_name, "Имена"), (changed_id, "ЕГН/ЛНЧ")) if condition)
    log(db, ses.user_id, "patient_edited", patient.id, details=f"Променени полета: {fields}")
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return fail("Това ЕГН/ЛНЧ вече е регистрирано.")
    return RedirectResponse(f"/patients/{patient.id}", status_code=303)


@app.post("/patients/{patient_id}/reset")
def reset_password(request: Request, patient_id: int, csrf: str = Form(""), db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    patient = get_patient(db, patient_id)
    password = secrets.token_urlsafe(18)
    patient.password_hash = ph.hash(password)
    patient.must_change_password = False
    # All patient sessions must be invalidated immediately.
    db.query(LoginSession).filter(LoginSession.user_id == patient.id).delete()
    log(db, ses.user_id, "patient_password_reset", patient.id)
    db.commit()
    return page(request, "credentials.html", user=ses.user, csrf=ses.csrf_token,
                patient=patient, username=patient.username, password=password, operation="Генерирана нова парола")


@app.post("/patients/{patient_id}/status")
def patient_status(request: Request, patient_id: int, csrf: str = Form(""), db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    patient = get_patient(db, patient_id)
    patient.active = not patient.active
    if not patient.active:
        db.query(LoginSession).filter(LoginSession.user_id == patient.id).delete()
    log(db, ses.user_id, "patient_activated" if patient.active else "patient_deactivated", patient.id)
    db.commit()
    return RedirectResponse(f"/patients/{patient.id}", status_code=303)


# FT8 prototype hook. Only the explicit temporary synthetic fixture installer
# enables it; existing deployments receive no new schema or automatic policy.
pdf_av_policy = None
pdf_scanner_precheck = None  # Enabled only by the explicit synthetic pilot entrypoint.

MAX_PDF = 15 * 1024 * 1024


# Never pass a filesystem path or an unauthenticated URI to the scan service.
# All clamd network traffic is restricted to localhost; the operator must
# independently manage daemon signature updates and access to its socket.
def scan_pdf_for_malware(path: Path) -> bool:
    """Return True only on explicit local clamd OK; never treat errors as clean.

    False means scanner OFF in development and is NOT a clean/approved result.
    Clamd INSTREAM is streamed in bounded chunks; response is parsed strictly.
    """
    if PDF_SCAN_MODE == "off":
        return False
    if pdf_scanner_precheck is not None:
        pdf_scanner_precheck()
    try:
        if path.stat().st_size > MAX_PDF:
            raise HTTPException(413, "Максималният размер на PDF е 15 MB.")
        reply = bytearray()
        deadline = time.monotonic() + 30.0
        with socket.create_connection(("127.0.0.1", PDF_SCAN_PORT), timeout=5.0) as conn:
            conn.settimeout(5.0)
            conn.sendall(b"zINSTREAM\0")
            with path.open("rb") as stream:
                total = 0
                while block := stream.read(64 * 1024):
                    total += len(block)
                    if total > MAX_PDF:
                        raise HTTPException(413, "Максималният размер на PDF е 15 MB.")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise OSError("scan deadline exceeded")
                    conn.settimeout(min(5.0, remaining))
                    conn.sendall(struct.pack("!I", len(block)))
                    conn.sendall(block)
            conn.sendall(b"\0\0\0\0")
            while len(reply) <= 1024:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OSError("scan deadline exceeded")
                conn.settimeout(min(5.0, remaining))
                block = conn.recv(min(256, 1025 - len(reply)))
                if not block:
                    break
                reply.extend(block)
                if b"\0" in block or b"\n" in block:
                    break
        # zINSTREAM requires a complete NUL-terminated, unambiguous verdict.
        # EOF after an unterminated "OK" is not a successful scan.
        if len(reply) > 1024 or not reply.endswith(b"\0") or b"\0" in reply[:-1]:
            raise HTTPException(503, "Невалиден отговор от PDF проверката.", headers={"Retry-After": "30"})
        result = bytes(reply[:-1])
        if result == b"stream: OK":
            return True
        if result.startswith(b"stream: ") and result.endswith(b" FOUND") and len(result) > 15:
            # Do not expose the malware signature or file contents to patients.
            raise HTTPException(422, "PDF документът е отхвърлен от проверката за сигурност.")
        raise HTTPException(503, "Проверката на PDF не е достъпна. Опитайте по-късно.",
                            headers={"Retry-After": "30"})
    except HTTPException:
        raise
    except (OSError, ValueError, OverflowError):
        raise HTTPException(503, "Проверката на PDF не е достъпна. Опитайте по-късно.",
                            headers={"Retry-After": "30"}) from None


def assert_pdf_unchanged_after_scan(path: Path, sha256_hex: str) -> None:
    """Reject modified upload between receipt, scanning, and DB insertion."""
    digest = hashlib.sha256()
    try:
        total = 0
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_PDF:
                    raise HTTPException(409, "PDF документът се е променил по време на проверката.")
                digest.update(chunk)
    except OSError:
        raise HTTPException(409, "PDF документът се е променил по време на проверката.") from None
    if not hmac.compare_digest(digest.hexdigest(), sha256_hex):
        raise HTTPException(409, "PDF документът се е променил по време на проверката.")

# Conservative container sanity check only. This is NOT an AV scanner,
# PDF sanitizer, JavaScript detector or substitute for an isolated parser.
def pdf_has_complete_trailer(path: Path) -> bool:
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        if size < 20 or size > MAX_PDF:
            return False
        stream.seek(max(0, size - 4096))
        trailer = stream.read()
    return bool(re.search(rb"startxref[ \t\r\n]+[0-9]+[ \t\r\n]+%%EOF[ \t\r\n]*\Z", trailer))


# Copies are intentionally bounded before returning an HTTP response. Never hand
# an unchecked, mutable filesystem path to FileResponse after hashing it: it
# would reopen that path later, potentially serving different bytes. Snapshotting
# is a deliberate memory/concurrency tradeoff; load testing is still required.
MAX_SERVED_PDF = 64 * 1024 * 1024  # legacy compatibility cap; uploads stay 15 MiB
# Per-process admission control for in-memory PDF HTTP responses. A slot is kept
# until Starlette finishes sending the response (or sending is cancelled).
# This is NOT a global capacity limit across workers or an overall RAM limit.
try:
    MAX_ACTIVE_PDF_DELIVERIES = int(os.environ.get('PORTAL_MAX_ACTIVE_PDF_DELIVERIES', '2'))
except ValueError as exc:
    raise RuntimeError('PORTAL_MAX_ACTIVE_PDF_DELIVERIES must be 1-4') from exc
if not 1 <= MAX_ACTIVE_PDF_DELIVERIES <= 4:
    raise RuntimeError('PORTAL_MAX_ACTIVE_PDF_DELIVERIES must be 1-4')
_pdf_delivery_slots = threading.BoundedSemaphore(MAX_ACTIVE_PDF_DELIVERIES)


class LeasedPdfResponse(Response):
    """Release the PDF admission slot even if ASGI delivery fails or is cancelled."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            _pdf_delivery_slots.release()



def snapshot_verified_pdf(doc: Report) -> tuple[bytes, str]:
    # Stored names are generated internally; reject a corrupt/legacy DB path
    # before resolving it. Filesystem ACL and non-writable code remain essential.
    name = doc.stored_name or ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", name):
        raise HTTPException(404)
    path = STORAGE / name
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(STORAGE):
        raise HTTPException(404)
    try:
        with path.open('rb') as stream:
            data = stream.read(MAX_SERVED_PDF + 1)
    except OSError:
        raise HTTPException(404, "PDF документът е недостъпен.") from None
    if len(data) > MAX_SERVED_PDF:
        raise HTTPException(409, "PDF документът надвишава границата за проверен достъп.")
    actual = hashlib.sha256(data).hexdigest()
    if doc.file_sha256 is not None and not hmac.compare_digest(actual, doc.file_sha256.lower()):
        raise HTTPException(409, "Целостта на PDF документа не може да бъде потвърдена.")
    return data, actual


def pdf_snapshot_response(data: bytes, report_id: int, *, inline: bool, preview: bool = False) -> LeasedPdfResponse:
    # Filename is generated from an integer ID; never use the uploaded filename.
    filename = f"preview_{report_id}.pdf" if preview else f"razchitane_{report_id}.pdf"
    disposition = "inline" if inline else "attachment"
    return LeasedPdfResponse(content=data, media_type="application/pdf", headers={
        "Content-Disposition": f'{disposition}; filename="{filename}"',
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
    })


def limited_pdf_delivery(doc: Report, *, db: Session, actor_id: int,
                         action: str, inline: bool, preview: bool = False) -> LeasedPdfResponse:
    """Bound simultaneous verified PDF responses and release permits on every path.

    All route authentication/authorization is performed BEFORE entering here.
    The permit covers the snapshot, audit commit and final ASGI body send.
    """
    if not _pdf_delivery_slots.acquire(blocking=False):
        raise HTTPException(503, "Временно ограничение на едновременните PDF заявки.",
                            headers={"Retry-After": "2", "Cache-Control": "no-store"})
    try:
        data, checksum = snapshot_verified_pdf(doc)
        if pdf_av_policy is not None:
            pdf_av_policy.require(db, doc.id, checksum)
        details = "sha256:" + checksum if preview else ("Отворен PDF" if inline else "Изтеглен PDF")
        log(db, actor_id, action, doc.id, details=details)
        db.commit()
        # LeasedPdfResponse owns the semaphore slot from this point forward.
        return pdf_snapshot_response(data, doc.id, inline=inline, preview=preview)
    except BaseException:
        _pdf_delivery_slots.release()
        raise


MODALITIES = ("ЯМР", "КТ", "Рентген", "Ехография", "Мамография", "Друго")

@app.post("/patients/{patient_id}/reports")
def upload_report(request: Request, patient_id: int, file: UploadFile = File(...),
                  title: str = Form(...), modality: str = Form(...), exam_date: date = Form(...),
                  csrf: str = Form(""), confirm_owner: str = Form(""), db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    patient = get_patient(db, patient_id)
    if confirm_owner != "yes":
        raise HTTPException(422, "Потвърдете самоличността на пациента.")
    title = title.strip()
    if not 2 <= len(title) <= 120 or modality not in MODALITIES or exam_date > now().date():
        raise HTTPException(422, "Невалидни данни за изследването.")
    if not (file.filename or "").lower().endswith(".pdf"):
        raise HTTPException(422, "Приемат се само PDF файлове.")
    original = Path((file.filename or "report.pdf").replace("\\", "/")).name[:180]
    safe_name = f"{uuid.uuid4().hex}.pdf"
    destination = STORAGE / safe_name
    total = 0
    digest = hashlib.sha256()
    try:
        with destination.open("xb") as out:
            magic = file.file.read(5)
            if magic != b"%PDF-":
                raise HTTPException(422, "Файлът не е валиден PDF.")
            out.write(magic)
            digest.update(magic)
            total = len(magic)
            while chunk := file.file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_PDF:
                    raise HTTPException(413, "Максималният размер на PDF е 15 MB.")
                out.write(chunk)
                digest.update(chunk)
        if not pdf_has_complete_trailer(destination):
            raise HTTPException(422, "Невалиден или непълен PDF документ.")
        destination.chmod(0o600)
        checksum = digest.hexdigest()
        # In production, a scanner must return an explicit clean verdict.
        # Scan failure/malware rejection is fail-closed and cleaned up below.
        scanned_clean = scan_pdf_for_malware(destination)
        assert_pdf_unchanged_after_scan(destination, checksum)
        # Avoid unintentionally uploading the same report twice for one patient.
        prior_reports = db.scalars(select(Report).where(Report.patient_id == patient.id,
            Report.revoked_at.is_(None))).all()
        for prior in prior_reports:
            if prior.file_sha256 == checksum:
                raise HTTPException(409, "Този PDF вече е качен за пациента.")
            if prior.file_sha256 is None:
                previous_file = STORAGE / prior.stored_name
                if previous_file.is_file() and previous_file.stat().st_size == total:
                    old_digest = hashlib.sha256()
                    with previous_file.open("rb") as old_stream:
                        for old_chunk in iter(lambda: old_stream.read(1024*1024), b""):
                            old_digest.update(old_chunk)
                    if old_digest.hexdigest() == checksum:
                        raise HTTPException(409, "Този PDF вече е качен за пациента.")
        doc = Report(patient_id=patient.id, uploaded_by=ses.user_id, title=title,
                     published_at=None,
                     modality=modality, exam_date=exam_date, stored_name=safe_name,
                     original_name=original, file_sha256=checksum)
        db.add(doc)
        db.flush()
        if pdf_av_policy is not None:
            pdf_av_policy.add_result(db, doc.id, checksum,
                                     'clean' if scanned_clean is True else 'unscanned',
                                     'clamd-instream-v1' if scanned_clean is True else 'scanner-off')
        log(db, ses.user_id, "report_draft_created", doc.id, details="Качен за преглед; все още не е публикуван")
        db.commit()
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        file.file.close()
    return RedirectResponse(f"/patients/{patient.id}", status_code=303)


@app.get("/reports/{report_id}/preview")
def preview_report(request: Request, report_id: int, db: Session = Depends(db_session)):
    # Top-level PDF preview (rather than iframe) works with the strict CSP.
    ses = require_auth(request, db, role="staff")
    doc = db.get(Report, report_id)
    if not doc or doc.revoked_at is not None:
        raise HTTPException(404)
    # Audit binds the preview to EXACT bytes sent; the slot spans the HTTP send.
    return limited_pdf_delivery(doc, db=db, actor_id=ses.user_id,
                                action="report_previewed", inline=True, preview=True)


@app.get("/reports/{report_id}/view")
def view_report(request: Request, report_id: int, db: Session = Depends(db_session)):
    ses = require_auth(request, db)
    doc = db.get(Report, report_id)
    if not doc or doc.revoked_at is not None:
        raise HTTPException(404)
    if ses.user.role != "staff" and (doc.patient_id != ses.user_id or doc.published_at is None):
        raise HTTPException(404)
    return limited_pdf_delivery(doc, db=db, actor_id=ses.user_id,
                                action="report_viewed", inline=True)


@app.post("/reports/{report_id}/publish")
def publish_report(request: Request, report_id: int, csrf: str = Form(""),
                   confirm_owner: str = Form(""), db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    doc = db.get(Report, report_id)
    if not doc or doc.revoked_at is not None:
        raise HTTPException(404)
    if doc.published_at is not None:
        raise HTTPException(409, "Документът вече е публикуван.")
    if confirm_owner != "yes":
        raise HTTPException(422, "Потвърдете, че документът е за правилния пациент.")
    # A preview must be linked to precisely the bytes being published.
    # A previous preview of altered bytes is not sufficient.
    data, checksum = snapshot_verified_pdf(doc)
    if len(data) > MAX_PDF or not re.search(
        rb"startxref[ \t\r\n]+[0-9]+[ \t\r\n]+%%EOF[ \t\r\n]*\Z", data[-4096:]
    ):
        raise HTTPException(422, "PDF документът не е завършен.")
    previewed = db.scalar(select(Audit.id).where(
        Audit.actor_id == ses.user_id, Audit.action == "report_previewed",
        Audit.target_id == doc.id, Audit.details == "sha256:" + checksum).limit(1))
    if previewed is None:
        raise HTTPException(422, "Първо прегледайте текущата версия на PDF документа.")
    if pdf_av_policy is not None:
        pdf_av_policy.require(db, doc.id, checksum)
    # Legacy un-hashed drafts become integrity-tracked when published.
    if doc.file_sha256 is None:
        doc.file_sha256 = checksum
    doc.published_at = now()
    log(db, ses.user_id, "report_published", doc.id, details="Публикувано за пациента")
    db.commit()
    return RedirectResponse(f"/patients/{doc.patient_id}", status_code=303)


@app.post("/reports/{report_id}/scan")
def scan_existing_report(request: Request, report_id: int, csrf: str = Form(""),
                         db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    if pdf_av_policy is None:
        raise HTTPException(404)
    doc = db.get(Report, report_id)
    if not doc or doc.revoked_at is not None:
        raise HTTPException(404)
    pdf_av_policy.scan_existing(sys.modules[__name__], db, doc, ses.user_id)
    return RedirectResponse(f"/patients/{doc.patient_id}", status_code=303)


@app.post("/reports/{report_id}/revoke")
def revoke_report(request: Request, report_id: int, csrf: str = Form(""), db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    check_csrf(ses, csrf)
    doc = db.get(Report, report_id)
    if not doc:
        raise HTTPException(404)
    if doc.revoked_at is not None:
        raise HTTPException(409, "Документът вече е оттеглен.")
    doc.revoked_at = now()
    log(db, ses.user_id, "report_revoked", doc.id,
        details="Оттеглен публикуван документ" if doc.published_at else "Оттеглена чернова")
    db.commit()
    return RedirectResponse(f"/patients/{doc.patient_id}", status_code=303)


@app.get("/reports/{report_id}/download")
def download_report(request: Request, report_id: int, db: Session = Depends(db_session)):
    ses = require_auth(request, db)
    doc = db.get(Report, report_id)
    if not doc or doc.revoked_at is not None:
        raise HTTPException(404)
    if ses.user.role != "staff" and (doc.patient_id != ses.user_id or doc.published_at is None):
        raise HTTPException(404)  # Do not disclose existence of other patients' reports.
    return limited_pdf_delivery(doc, db=db, actor_id=ses.user_id,
                                action="report_downloaded", inline=False)


@app.get("/change-password")
def change_password_form(request: Request, db: Session = Depends(db_session)):
    ses = require_auth(request, db)
    return page(request, "change_password.html", user=ses.user, csrf=ses.csrf_token)


@app.post("/change-password")
def change_password(request: Request, current_password: str = Form(...),
                    new_password: str = Form(...), confirm_password: str = Form(...),
                    csrf: str = Form(""), db: Session = Depends(db_session)):
    ses = require_auth(request, db)
    check_csrf(ses, csrf)
    err = ""
    try:
        valid_old = ph.verify(ses.user.password_hash, current_password)
    except (VerificationError, VerifyMismatchError):
        valid_old = False
    if not valid_old:
        err = "Текущата парола е грешна."
    elif len(new_password) < 12 or len(new_password) > 128:
        err = "Новата парола трябва да е между 12 и 128 символа."
    elif new_password != confirm_password:
        err = "Паролите не съвпадат."
    elif new_password == current_password:
        err = "Новата парола трябва да е различна."
    if err:
        return page(request, "change_password.html", user=ses.user, csrf=ses.csrf_token,
                    error=err, status_code=422)
    ses.user.password_hash = ph.hash(new_password)
    ses.user.must_change_password = False
    # Invalidate concurrent sessions, keep only the current one.
    db.query(LoginSession).filter(LoginSession.user_id == ses.user_id, LoginSession.id != ses.id).delete(synchronize_session=False)
    log(db, ses.user_id, "password_changed")
    db.commit()
    return RedirectResponse("/dashboard", status_code=303)


AUDIT_ACTIONS = {
    "login_success": "Успешен вход", "login_failed": "Неуспешен вход",
    "logout": "Изход", "patient_created": "Създаден пациент",
    "patient_edited": "Редактиран пациент", "patient_password_reset": "Нова пациентска парола",
    "patient_activated": "Активиран пациент", "patient_deactivated": "Спрян пациент",
    "report_uploaded": "Качено разчитане (стара версия)",
    "report_draft_created": "Създадена чернова", "report_previewed": "Преглед на PDF",
    "report_av_checked": "Антивирусна проверка на PDF",
    "report_published": "Публикувано разчитане", "report_revoked": "Оттеглено разчитане",
    "report_downloaded": "Изтеглен PDF", "password_changed": "Сменена парола",
    "credentials_pdf_exported": "Издадени данни за вход (PDF)",
    "report_viewed": "Отворен PDF", "center_settings_updated": "Редактирани настройки",
    "center_logo_updated": "Сменено лого",
    "staff_password_reset_local": "Нулирана служебна парола локално",
    "staff_mfa_enrolled_local": "Включена двуфакторна защита",
}


@app.get("/audit")
def audit_page(request: Request, action: str = "all", page_num: int = 1,
               db: Session = Depends(db_session)):
    ses = require_auth(request, db, role="staff")
    action = action if action in AUDIT_ACTIONS else "all"
    query = select(Audit)
    if action != "all":
        query = query.where(Audit.action == action)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    last_page = max(1, (total + 49) // 50)
    page_num = min(normalize_page(page_num), last_page)
    records = db.scalars(query.order_by(Audit.id.desc()).limit(50).offset((page_num - 1) * 50)).all()
    actor_ids = {row.actor_id for row in records if row.actor_id is not None}
    patient_ids = {row.target_id for row in records if row.target_id is not None and row.action.startswith("patient_")}
    names = {}
    if actor_ids or patient_ids:
        for u in db.scalars(select(User).where(User.id.in_(actor_ids | patient_ids))).all():
            names[u.id] = u.full_name
    display_rows = []
    for row in records:
        actor = names.get(row.actor_id, f"Потребител №{row.actor_id}") if row.actor_id else "Система / непознат"
        if row.target_id is None:
            target = "—"
        elif row.action.startswith("patient_"):
            target = f"Пациент №{row.target_id}"  # avoid showing raw EGN
        elif row.action.startswith("report_"):
            target = f"Документ №{row.target_id}"
        elif row.action == "credentials_pdf_exported":
            target = f"Пациент №{row.target_id}"
        else:
            target = f"Обект №{row.target_id}"
        display_rows.append({"date": row.occurred_at, "actor": actor,
                             "action": AUDIT_ACTIONS.get(row.action, row.action),
                             "target": target, "details": row.details or "—"})
    return page(request, "audit.html", user=ses.user, csrf=ses.csrf_token,
                records=display_rows, actions=AUDIT_ACTIONS, action_filter=action,
                page_num=page_num, last_page=last_page, total=total)


@app.exception_handler(403)
def forbidden(request: Request, exc: HTTPException):
    return page(request, "error.html", status_code=403, title="Нямате достъп", explanation="Това действие не е разрешено.")

@app.exception_handler(404)
def notfound(request: Request, exc: HTTPException):
    return page(request, "error.html", status_code=404, title="Страницата не е намерена", explanation="Проверете адреса или се върнете в портала.")


@app.get("/healthz", include_in_schema=False)
def healthz():
    # Kept deliberately shallow; do not leak host/database information.
    return Response("ok", media_type="text/plain", headers={"Cache-Control": "no-store"})
