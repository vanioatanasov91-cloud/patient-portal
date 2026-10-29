"""Authenticated offline backups of a NEW synthetic candidate, never a live store.

Uses the existing AES-256-GCM/scrypt envelope and hash manifest. Includes the
candidate marker and secret; runtime locks are recreated, never copied/restored.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import tempfile

from candidate_runtime import read_config,root_path,create_lifecycle,acquire_lifecycle,CandidateError
import secure_backup

METADATA=('candidate.json','candidate-secret','synthetic-accounts.json')


@contextmanager
def source_environment(root):
    values={'DATABASE_URL':'sqlite:///'+(root/'candidate.sqlite3').as_posix(),'PRIVATE_STORAGE':str(root/'files')}
    before={k:os.environ.get(k) for k in values}
    os.environ.update(values)
    try:yield
    finally:
        for key,value in before.items():
            if value is None:os.environ.pop(key,None)
            else:os.environ[key]=value


def create(data,output,passphrase):
    root,config=read_config(data)
    lease=acquire_lifecycle(root,config['instance_id'],exclusive=True)
    try:
        for name in METADATA:
            path=root/name
            if path.is_symlink() or not path.is_file() or path.stat().st_nlink!=1:
                raise CandidateError('HOLD: invalid synthetic backup metadata')
        with source_environment(root):
            return secure_backup.create_backup(Path(output),passphrase,extra_files={n:root/n for n in METADATA})
    finally:lease.close()


def restore(archive,destination,passphrase):
    destination=root_path(destination)
    if destination.exists():raise CandidateError('HOLD: restore destination must not exist')
    if os.environ.get('PORTAL_ENV','').lower()=='production':
        raise CandidateError('HOLD: synthetic restore is forbidden in production')
    # Complete authentication and hash validation BEFORE publishing any store.
    with tempfile.TemporaryDirectory(prefix='.candidate-restore-',dir=destination.parent) as temp:
        payload=Path(temp)/'payload'
        count=secure_backup.verify_or_restore(Path(archive),passphrase,payload,candidate_metadata=True)
        if not all((payload/n).is_file() for n in METADATA):
            raise CandidateError('HOLD: missing candidate metadata in backup')
        (payload/'portal.sqlite3').rename(payload/'candidate.sqlite3')
        (payload/'uploads').rename(payload/'files')
        import json
        config=json.loads((payload/'candidate.json').read_text())
        from shared_pdf_admission import DiskSlotPool
        state=payload/'shared-admission';state.mkdir(mode=0o700)
        DiskSlotPool.prepare(state/'total',2);DiskSlotPool.prepare(state/'uploads',1)
        create_lifecycle(payload,config['instance_id'])
        for name in METADATA+('candidate.sqlite3',):(payload/name).chmod(0o600)
        for folder in [payload/'files',*(p for p in (payload/'files').rglob('*') if p.is_dir())]:folder.chmod(0o700)
        read_config(payload)  # marker/schema/gate validation, still not published
        # rename avoids replacing an existing non-empty directory; check again
        # immediately before publishing our authenticated synthetic payload.
        if destination.exists():raise CandidateError('HOLD: restore destination appeared during validation')
        payload.rename(destination)
    return count
