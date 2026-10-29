# Fast Track 14 — действителен пилотен резултат

**HOLD / NO-GO. Само Linux synthetic пилот, без независимо одобрение.**

Изпълнен е shipping init/serve/status/offline lifecycle в наличната Linux/UID1000 managed Docker среда. Новата private директория е `/workspace/PatientPortal-pilot-v14`, извън source. Тя пази normal candidate/schema2, synthetic accounts/secret, PDF/AV evidence, immutable CVD snapshot и pilot marker/schema1. В ZIP няма никакви от тези runtime данни.

Истинският official FreshClam подготви persistent snapshot. Startup offline CVD verification и реален PING/clean/EICAR/48h preflight минаха. Normal foreground pilot стартира с2 HTTP workers, HTTP127.0.0.1:18080 и ClamAV127.0.0.1:13310. Scanner-ът е non-root/read-only,2GiB/2CPU, само config/signature mounts, без candidate DB/PDF. Няма OS service/public preview/firewall/ACL промяна.

Отделният explicit real pilot acceptance мина **25/25 проверки**, exit0/PASS/HOLD: staff/patient/other login, held legacy, per-request readiness+real clean INSTREAM upload, byte-exact preview/publish/owner download, other404, CSRF, embedded EICAR422/no orphan, shared2-slot503/Retry-After,32 concurrent requests с точни200 или503, explicit legacy rescan/recovery, controlled stop/preserved data, encrypted offline backup/restore, original session/document/AV evidence след pilot restart и normal restored candidate start, SQLite integrity и owned-container cleanup. Точните времена и concurrency counts са в reports/last_pilot_acceptance.json. Temporary restore/archives/processes са премахнати; основният synthetic store е запазен за преглед.

Първият immediate restart беше отказан от прекалено строг plain bind при scanner port TIME_WAIT. Коригиран е SO_REUSEADDR precheck, който продължава да отказва active listener; целият real acceptance после е повторен успешно. Това не спира/заема чужда услуга.

Default suite остава18 групи; group17 първо изпълнява original42 candidate assertions, после8 mock/synthetic pilot cases. Unit coverage включва stale/future/truncated503 преди INSTREAM без report/orphan, no silent revoke на clean документ, guarded rescan, HTTP restart със запазена session, no overwrite/production/source writes, mutex/lifecycle/cooldown, modified gate/hash/unsigned database refusal и no unrelated cleanup. Default suite не стартира реален Docker/download. Actual регресионен резултат е в TEST_REPORT_BG.md.

Foreground пилотът работи само докато serve/облачната среда са активни; няма boot service, гарантиран24/7 uptime или автоматичен update timer. Операторът планира explicit offline daily refresh/backup. Cloud localhost не е публичен browser линк. Следва независим reviewer и отделен целеви access/HTTPS/Windows/deployment/security/privacy/GDPR/restore review. **HOLD / NO-GO остава.**

## Финално оставено състояние

Към 29.10.2026 09:23:17 EET: supervisor lock held, HTTP ready, scanner fresh, ready true. Пилотът е оставен foreground в текущата cloud сесия на127.0.0.1:18080, scanner13310; достъпът е от самия executor. Данните са в отделната private pilot папка; пароли/DB/PDF не са в source/ZIP.

Контролираният real scanner outage на 29.10.2026 09:21:18 EET завърши с owned HTTP/container cleanup и запазени данни; normal serve после възстанови ready status. Evidence: reports/last_pilot_recovery.json и reports/last_pilot_status.json. Това не гарантира постоянен runtime след затваряне на облачната среда и не заменя независим reviewer.
