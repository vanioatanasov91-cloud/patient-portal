# Fast Track 14 — действителен отчет

**HOLD / NO-GO. Само synthetic Linux пилот; няма production или независимо одобрение.**

## Default regression suite

`python -B tools/fasttrack_runner.py --include-synthetic` → **18/18 PASS**, всички планирани групи са изпълнени. Отчет: 29.10.2026 09:18:33 EET. Linux/Python3.12.14, същият isolated venv извън source, без нови host Python packages.

| Група | Резултат | Секунди |
| --- | --- | --- |
| static | PASS | 0.121 |
| dr | PASS | 0.546 |
| ui | PASS | 1.931 |
| security | PASS | 2.065 |
| pdf | PASS | 1.403 |
| snapshot | PASS | 1.268 |
| admission | PASS | 1.198 |
| scan | PASS | 1.741 |
| legacy_inventory | PASS | 0.142 |
| concurrency | PASS | 0.855 |
| legacy_policy_v8 | PASS | 1.143 |
| clamd_preflight_v8 | PASS | 0.936 |
| http_load_v8 | PASS | 2.841 |
| shared_admission_v9 | PASS | 0.483 |
| ingress_v9 | PASS | 0.419 |
| resource_load_v9 | PASS | 34.709 |
| candidate_workflow_v10 | PASS | 16.02 |
| candidate_backup_v11 | PASS | 4.704 |

Всички предишни test source файлове са byte-for-byte непроменени. Група17 първо изпълнява оригиналните42 candidate assertions, след това8 нови pilot cases: VERSION/48h/stale/future/malformed, state/hash/unsigned DB/gate refusal, cross-process singleton/offline update exclusion, candidate worker lifecycle guard, no overwrite/production/source writes, hourly cooldown, unrelated-resource cleanup refusal, active listener conflict и normal pilot HTTP per-scan refusal/restart. Старите групи не са skipped/заменени; default suite не прави real Docker/download.

Core portal.py има само3-line nullable precheck hook. Candidate runtime приема explicit optional precheck; pilot entry го включва. Normal candidate/legacy default не променя поведението си. PDF AV/shared admission, candidate schema/config2, backup API, URLs/български workflow са запазени; UI label е v1.14. Pilot management schema1 е отделна, без adoption/migration/overwrite на стари stores.

## Реален foreground пилот

Нова private runtime папка: `/workspace/PatientPortal-pilot-v14`, извън всички source releases. Shipping init подготви official FreshClam snapshot; normal serve стартира2 workers и собствен labelled loopback ClamAV с read-only verified CVD mount, без candidate DB/PDF mounts. Startup digital signature/PING/clean/EICAR/48h preflight е passed. Подробности: PILOT_BG.md/PILOT_REPORT_BG.md.

`pilot_acceptance.py --confirm-synthetic-pilot-exercise` → **25/25 PASS**, exit0/PASS/HOLD. Изпълнение: 29.10.2026 09:13:40 EET → 29.10.2026 09:14:17 EET. Реални staff/patient/other входове, legacy423, readiness+INSTREAM clean upload, exact preview/publish/owner delivery, other404, CSRF, embedded EICAR422/no orphan, shared admission/Retry-After, explicit legacy rescan, controlled stop, authenticated encrypted backup/restore и session/document/AV evidence след normal pilot restart и restored normal candidate HTTP. SQLite integrity е ok. Acceptance temporary processes/archive/restored copies са премахнати; основните synthetic данни са запазени.

32 concurrent HTTP заявки: **6 ×200** с точните байтове и **26 ×503** при ограничения shared2-slot capacity. Това доказва bounded admission/recovery, не че всички32 трябва да бъдат обслужени или production capacity.

При first immediate restart port precheck беше отказал TIME_WAIT като зает scanner listener. Коригиран е с SO_REUSEADDR; активен чужд listener продължава да се отказва. Целият real acceptance е повторен успешно след корекцията.

## Реален scanner outage и възстановяване

Допълнително спиране само на собствения verified/labelled scanner: supervisor-ът спря своите HTTP workers, освободи lock и премахна собствения container, без data loss. Отчет: 29.10.2026 09:21:18 EET → 29.10.2026 09:21:21 EET, PASS/HOLD. След нормален serve със същия store scanner/HTTP са ready. Exact machine evidence: reports/last_pilot_recovery.json.

Последен status: **ready true**, scanner_fresh true, http_ready true на 29.10.2026 09:23:17 EET. Foreground pilot е оставен работещ за текущата cloud сесия на **127.0.0.1:18080**, clamd127.0.0.1:13310. Това е localhost на executor-а; достъпът е от самата среда. Няма публичен preview, OS service или гарантиран24/7 uptime. При спиране/изключване на средата процесите приключват; persistent synthetic data се запазват според lifecycle на workspace.

## Оставащо преди реални данни

Независим reviewer/sign-off не е извършен. Няма Windows/HTTPS/reverse-proxy/firewall/ACL/BitLocker или real DB migration. Няма auto-update timer; операторът планира explicit offline daily refresh/backup, със startup/per-scan48h fail-closed guard. Engine/signature provenance/retention, security/privacy/GDPR/DPIA, independent DR и целеви OS/capacity review остават. Нито зелените Codex тестове, нито source SHA256 списъците са независимо одобрение/цифров release подпис. **HOLD / NO-GO остава.**
