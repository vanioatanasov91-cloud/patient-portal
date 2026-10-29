"""FT11 runnable synthetic candidate with offline lifecycle guard. New isolated stores only, never deployment.

Default legacy portal startup is unchanged. The candidate entrypoint validates its
own versioned store BEFORE importing the backend that has legacy import-time DDL.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import date
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import secrets
import sqlite3
import sys
import uuid

APP = Path(__file__).resolve().parent
PROJECT = APP.parent
KIND = 'PatientPortalSyntheticCandidate'
GATE = 'HOLD / NO-GO'
REQUIRED = {
    'users': {'id','username','full_name','password_hash','role','active','must_change_password','mfa_secret_enc','created_at'},
    'login_sessions': {'id','token_hash','user_id','csrf_token','mfa_verified','expires_at','created_at'},
    'reports': {'id','patient_id','uploaded_by','modality','title','exam_date','stored_name','original_name',
                'uploaded_at','revoked_at','published_at','file_sha256'},
    'audit': {'id','actor_id','action','target_id','occurred_at','details'},
    'auth_failures': {'id','fingerprint','occurred_at'},
    'center_settings': {'id','center_name','phone','email','address','website','logo_filename'},
    'candidate_pdf_av_attestations': {'id','report_id','schema_version','sha256','verdict','source','scanned_at_utc'},
    'candidate_schema': {'version','instance_id'},
}


class CandidateError(RuntimeError): pass


def private_write(path, text):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as out: out.write(text)


def root_path(path):
    path = Path(path).expanduser()
    if path.is_symlink(): raise CandidateError('HOLD: symbolic data directory is not supported')
    root = path.resolve()
    if root.is_relative_to(PROJECT):
        raise CandidateError('HOLD: candidate data must stay outside the source bundle')
    return root


def read_config(path):
    if os.environ.get('PORTAL_ENV','').lower() == 'production':
        raise CandidateError('HOLD: candidate cannot run in production mode')
    root = root_path(path)
    try:
        marker = root/'candidate.json'
        if marker.is_symlink() or not marker.is_file(): raise ValueError()
        config = json.loads(marker.read_text(encoding='utf-8'))
        if not isinstance(config,dict): raise ValueError()
        if (config.get('kind') != KIND or config.get('version') != 2 or config.get('state') != 'ready'
                or config.get('release_gate') != GATE or config.get('synthetic_only') is not True
                or not isinstance(config.get('instance_id'),str) or not re.fullmatch('[0-9a-f]{32}',config['instance_id'])
                or type(config.get('scanner_port')) is not int or not 1 <= config['scanner_port'] <= 65535
                or config.get('pdf_slots') != 2 or config.get('upload_slots') != 1):
            raise ValueError()
        for name in ('candidate.sqlite3','candidate-secret','candidate-lifecycle.sqlite3','files','shared-admission'):
            if (root/name).is_symlink() or not (root/name).exists(): raise ValueError()
        for name in ('candidate.sqlite3','candidate-secret','candidate-lifecycle.sqlite3'):
            if not (root/name).is_file() or (root/name).stat().st_nlink != 1: raise ValueError()
        for name in ('files','shared-admission'):
            if not (root/name).is_dir(): raise ValueError()
        for pool,capacity in (('total',2),('uploads',1)):
            for index in range(capacity):
                slot=root/'shared-admission'/pool/f'slot-{index}'
                if slot.is_symlink() or not slot.is_file() or slot.stat().st_size != 1 or slot.stat().st_nlink != 1:
                    raise ValueError()
        if len((root/'candidate-secret').read_text().strip()) < 48: raise ValueError()
        # Read-only inspection: rejected/old/unmarked databases never reach the
        # backend import, automatic legacy migrations, seeds or schema creation.
        with sqlite3.connect((root/'candidate.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
            for table, columns in REQUIRED.items():
                actual = {r[1] for r in db.execute(f'PRAGMA table_info("{table}")')}
                if not columns <= actual: raise ValueError()
            rows = db.execute('SELECT version, instance_id FROM candidate_schema').fetchall()
            if rows != [(2, config['instance_id'])]: raise ValueError()
            if db.execute('PRAGMA foreign_key_check').fetchone() is not None: raise ValueError()
    except (OSError,ValueError,TypeError,sqlite3.Error) as exc:
        raise CandidateError('HOLD: missing, incompatible or unprepared synthetic candidate store') from exc
    # The separate guard DB has no patient records and uses DELETE journaling.
    # Shared read transactions in every server process exclude offline backup.
    try:
        with sqlite3.connect((root/'candidate-lifecycle.sqlite3').as_uri()+'?mode=ro',uri=True) as guard:
            if guard.execute('SELECT instance_id FROM lease_marker').fetchall()!=[(config['instance_id'],)]:
                raise ValueError()
    except (sqlite3.Error,ValueError) as exc:
        raise CandidateError('HOLD: incompatible candidate lifecycle guard') from exc
    return root,config


@contextmanager
def backend_environment(root,config):
    if (APP/'.env').exists():
        raise CandidateError('HOLD: candidate source must not contain an app/.env file')
    values = {
        'PORTAL_ENV':'candidate','PORTAL_CANDIDATE_INSTANCE':config['instance_id'], 'PORTAL_SECRET':(root/'candidate-secret').read_text().strip(),
        'DATABASE_URL':'sqlite:///'+(root/'candidate.sqlite3').as_posix(),
        'PRIVATE_STORAGE':str(root/'files'),'PORTAL_COOKIE_SECURE':'0',
        'PORTAL_ALLOWED_HOSTS':'127.0.0.1,localhost', 'PORTAL_PDF_SCAN_MODE':'clamd',
        'PORTAL_PDF_SCAN_PORT':str(config['scanner_port']), 'PORTAL_MAX_ACTIVE_PDF_DELIVERIES':'2',
    }
    before = {name:os.environ.get(name) for name in values}
    os.environ.update(values)
    try: yield
    finally:
        for name,value in before.items():
            if value is None:os.environ.pop(name,None)
            else:os.environ[name]=value


def load_backend(root,config):
    name='pp_candidate_'+config['instance_id']
    if name in sys.modules: raise CandidateError('HOLD: candidate backend is already loaded in this process')
    with backend_environment(root,config):
        spec=importlib.util.spec_from_file_location(name,APP/'portal.py')
        portal=importlib.util.module_from_spec(spec)
        sys.modules[name]=portal
        try:spec.loader.exec_module(portal)
        except BaseException:
            sys.modules.pop(name,None)
            raise
    from sqlalchemy import event
    @event.listens_for(portal.engine,'connect')
    def foreign_keys(connection,_):
        connection.execute('PRAGMA foreign_keys=ON')
    # Drop pre-existing pooled initialization connections; all future connections
    # get FK enforcement, including upload/attestation transactions in workers.
    portal.engine.dispose()
    return portal


def schema(portal):
    from sqlalchemy import CheckConstraint,Column,ForeignKeyConstraint,Integer,String,Table
    from legacy_pdf_policy import attestations
    table=attestations.to_metadata(portal.Base.metadata,name='candidate_pdf_av_attestations')
    table.append_constraint(ForeignKeyConstraint(['report_id'],['reports.id'],ondelete='RESTRICT'))
    table.append_constraint(CheckConstraint('schema_version = 1'))
    table.append_constraint(CheckConstraint("verdict IN ('pending','clean','infected','error','unscanned')"))
    table.append_constraint(CheckConstraint("length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'"))
    table.append_constraint(CheckConstraint("source IN ('clamd-instream-v1','scanner-off')"))
    version=Table('candidate_schema',portal.Base.metadata,
                  Column('version',Integer,primary_key=True),Column('instance_id',String(32),nullable=False))
    return table,version


def initialize(path, *, scanner_port=3310):
    if os.environ.get('PORTAL_ENV','').lower()=='production':
        raise CandidateError('HOLD: synthetic initialization is forbidden in production')
    if not 1 <= scanner_port <= 65535: raise CandidateError('HOLD: invalid local scanner port')
    root=root_path(path)
    # No in-place upgrade, backfill, reset, re-seeding or overwrite is provided.
    root.mkdir(mode=0o700)
    config={'kind':KIND,'version':2,'state':'initializing','release_gate':GATE,'synthetic_only':True,
            'instance_id':uuid.uuid4().hex,'scanner_port':scanner_port,'pdf_slots':2,'upload_slots':1}
    private_write(root/'candidate.json',json.dumps(config,indent=2))
    private_write(root/'candidate-secret',secrets.token_urlsafe(48))
    (root/'files').mkdir(mode=0o700)
    portal=load_backend(root,config)
    try:
        table,version=schema(portal)
        portal.Base.metadata.create_all(portal.engine)  # brand-new isolated DB ONLY
        from sqlalchemy import insert
        accounts=[]
        with portal.SessionLocal() as db:
            users=[]
            for username,name,role in [('synthetic_staff','Синтетичен служител','staff'),
                                       ('synthetic_patient','Синтетичен пациент','patient'),
                                       ('synthetic_other','Друг синтетичен пациент','patient')]:
                password=secrets.token_urlsafe(24)
                user=portal.User(username=username,full_name=name,role=role,active=True,
                                 password_hash=portal.ph.hash(password),must_change_password=False)
                db.add(user);db.flush();users.append(user)
                accounts.append({'username':username,'password':password,'role':role})
            from reportlab.pdfgen import canvas
            data=io.BytesIO();pdf=canvas.Canvas(data)
            pdf.drawString(60,700,'SYNTHETIC LEGACY DOCUMENT - NO AV ATTESTATION');pdf.save()
            (root/'files/synthetic-legacy.pdf').write_bytes(data.getvalue())
            (root/'files/synthetic-legacy.pdf').chmod(0o600)
            db.add(portal.Report(patient_id=users[1].id,uploaded_by=users[0].id,modality='ЯМР',
                                 title='Синтетичен наследен документ',exam_date=date(2020,1,1),
                                 stored_name='synthetic-legacy.pdf',original_name='synthetic-legacy.pdf',
                                 published_at=portal.now(),file_sha256=None))
            db.add(portal.CenterSettings(id=1,center_name='Синтетичен тестов център'))
            db.execute(insert(version).values(version=2,instance_id=config['instance_id']))
            db.commit()
        from shared_pdf_admission import DiskSlotPool
        state=root/'shared-admission';state.mkdir(mode=0o700)
        DiskSlotPool.prepare(state/'total',2);DiskSlotPool.prepare(state/'uploads',1)
        create_lifecycle(root,config['instance_id'])
        private_write(root/'synthetic-accounts.json',json.dumps({'synthetic_only':True,'accounts':accounts},ensure_ascii=False,indent=2))
        config['state']='ready'
        private_write(root/'candidate.next',json.dumps(config,indent=2))
        (root/'candidate.next').replace(root/'candidate.json')
    finally:portal.engine.dispose()
    read_config(root)
    return root


def build_app(path, *, scanner_precheck=None):
    root,config=read_config(path)
    # Validate the existing pools before backend import, never recreate missing
    # slots during startup or replace live lock state.
    from shared_pdf_admission import DiskSlotPool,SharedPdfAdmission
    total=DiskSlotPool(root/'shared-admission/total',2)
    uploads=DiskSlotPool(root/'shared-admission/uploads',1)
    lease=acquire_lifecycle(root,config['instance_id'])
    try:
        portal=load_backend(root,config)
        table,_=schema(portal)
    except BaseException:
        lease.close()
        raise
    from legacy_pdf_policy import AvPolicy
    portal.pdf_av_policy=AvPolicy(root,table=table)
    portal.pdf_scanner_precheck=scanner_precheck
    portal.templates.env.globals['candidate_mode']=True
    return LifecycleApp(SharedPdfAdmission(portal.app,total,uploads),lease)


class LifecycleLease:
    def __init__(self,connection):self.connection=connection
    def close(self):
        if self.connection is not None:
            connection,self.connection=self.connection,None
            connection.close()


def create_lifecycle(root,instance_id):
    path=root/'candidate-lifecycle.sqlite3'
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
    with sqlite3.connect(path) as guard:
        guard.execute('PRAGMA journal_mode=DELETE')
        guard.execute('CREATE TABLE lease_marker (instance_id TEXT NOT NULL)')
        guard.execute('INSERT INTO lease_marker VALUES (?)',(instance_id,))


def acquire_lifecycle(root,instance_id,*,exclusive=False):
    connection=None
    try:
        connection=sqlite3.connect((root/'candidate-lifecycle.sqlite3').as_uri()+'?mode=rw',uri=True,timeout=0,
                                   check_same_thread=False)
        connection.execute('BEGIN EXCLUSIVE' if exclusive else 'BEGIN')
        if connection.execute('SELECT instance_id FROM lease_marker').fetchall()!=[(instance_id,)]:
            raise ValueError()
        return LifecycleLease(connection)
    except (sqlite3.Error,ValueError) as exc:
        if connection is not None:connection.close()
        raise CandidateError('HOLD: candidate is serving or offline maintenance is active') from exc


class LifecycleApp:
    def __init__(self,app,lease):self.app,self.lease=app,lease
    async def __call__(self,scope,receive,send):
        try:return await self.app(scope,receive,send)
        finally:
            if scope['type']=='lifespan':self.lease.close()
