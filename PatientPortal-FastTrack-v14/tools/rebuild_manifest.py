#!/usr/bin/env python3
"""Manual maintenance utility: regenerate SHA256 allowlist for candidate source.

Run only after reviewing diffs. Does not approve production or make signatures.
"""
from pathlib import Path
import hashlib
import json

root=Path(__file__).resolve().parents[1]
exclude={'MANIFEST_SHA256.json','RELEASE_SHA256.json'}
allowed={'.md','.ps1','.py','.txt'}
records={}
for f in sorted(root.rglob('*')):
    if not f.is_file() or f.is_symlink():continue
    rel=f.relative_to(root).as_posix()
    if rel in exclude or rel.startswith(('reports/','.git/','__pycache__/')) or '__pycache__' in f.parts:
        continue
    if (f.suffix.lower() not in allowed and f.name != '.gitignore' and f.suffix.lower() not in {'.html','.css','.js'}):
        raise SystemExit('Unexpected file type; review before hashing: '+rel)
    records[rel]=hashlib.sha256(f.read_bytes()).hexdigest()
manifest=root/'MANIFEST_SHA256.json'
manifest.write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
release=dict(records)
release['MANIFEST_SHA256.json']=hashlib.sha256(manifest.read_bytes()).hexdigest()
(root/'RELEASE_SHA256.json').write_text(json.dumps(release,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(f'Source manifest regenerated: {len(records)} files. HOLD / NO-GO remains.')
