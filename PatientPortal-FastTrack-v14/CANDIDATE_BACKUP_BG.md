# Fast Track 14 — пълен криптиран offline backup/restore на synthetic кандидата

**HOLD / NO-GO. Само новият synthetic store, никога реални пациентски данни.**

V14 използва **candidate schema/config 2**. Инициализирай нова `PatientPortal-v14-data` директория; няма in-place upgrade/backfill на v10/schema 1 или друга съществуваща DB. V10 и неговите данни остават отделно. AV record schema остава version 1; lifecycle schema change е отделен runtime договор.

## Какво се пази

Съществуващият AES-256-GCM + scrypt + authenticated hash manifest формат запазва SQLite snapshot и PDF файловете. Новият кандидат wrapper добавя към същия **криптиран** архив:

- candidate.json (identity/schema/gate/scanner config);
- candidate-secret (постоянният приложен ключ);
- synthetic-accounts.json (само генерираните тестови credentials).

Нито ключът, нито паролите се отпечатват, слагат в аргументи или се включват в кодовия ZIP. Passphrase се въвежда локално чрез getpass; загубената passphrase не се възстановява. Няма криптиране на целия host диск от този инструмент; staging данните са plaintext и затова тази итерация допуска само synthetic данни.

Default legacy `app/secure_backup.py` форматът и allowlist са запазени. Candidate metadata е позволена само чрез явния wrapper; legacy restore не започва тихо да приема нови member имена.

## Защо backup е offline

Нормалният server supervisor и **всеки worker** държат shared read transaction в отделна `candidate-lifecycle.sqlite3` (няма patient records). Backup иска exclusive transaction с timeout 0. При жив normal server/worker backup отказва преди създаване на архив; server не започва при активна offline maintenance операция. ОС освобождава SQLite locks при exit. Работният application DB не е заключен за нормални writes от този отделен guard.

Не се разчита само на свободни PDF slots — login/audit също могат да пишат. Guard-ът предпазва нормалните entrypoints от случаен конкурентен старт; не е защита срещу администратор, който подменя guard/DB файлове или стартира непозволен код.

## Команди

Спри **собствения локален кандидат** с Ctrl+C и изчакай worker-ите. Не спирай реални услуги. От source папката, с изолирания venv:

```bash
python -B tools/candidate_backup.py create --data-dir ../PatientPortal-v14-data --output ../PatientPortal-v14-backup.ppbk --confirm-offline-synthetic-store
python -B tools/candidate_backup.py restore --file ../PatientPortal-v14-backup.ppbk --destination ../PatientPortal-v14-restored --confirm-synthetic-restore
python -B tools/run_candidate.py check --data-dir ../PatientPortal-v14-restored
python -B tools/run_candidate.py serve --data-dir ../PatientPortal-v14-restored
```

Backup output трябва да е извън data директорията и да не съществува. Restore destination също **не трябва да съществува**; няма overwrite. Операторският passphrase prompt е TTY-only, без стойност в chat/command line. API-то и реалният restore/start path са изпитани автоматично; интерактивният Windows prompt/ACL не е валидиран в Linux.

Restore удостоверява целия GCM ciphertext и всеки file hash в временна частна директория, после проверява marker/schema/gate. Runtime shared slots и lifecycle guard се **създават наново**, не се копират stale locks. Само след успех store-ът се публикува на новата destination директория. Грешна passphrase, променен authentication tag, липсващи metadata или existing destination са отказ.

## Доказателства

Група 18 проверява live/worker-style exclusion, пълен authenticated roundtrip, negative wrong-key/tamper, no overwrite, нов runtime state, възстановени normal HTTP session/legacy hold и legacy format compatibility. Допълнителният real-ClamAV lab възстанови и реално сканиран published PDF с AV evidence. Това не е независим disaster-recovery sign-off за реална инсталация.
