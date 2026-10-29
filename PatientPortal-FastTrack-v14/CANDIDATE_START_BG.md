# Fast Track 14 — стартиране на работещия изолиран кандидат

**HOLD / NO-GO. Само синтетични данни. Това не е внедряване върху реална инсталация.**

V14 има нормални `init`, `check`, `serve` команди. PDF AV политиката и общият limiter се включват автоматично от `app/candidate_entry.py`, без тестови monkeypatch-и и без извикване на fixture installer. Клиентът към clamd е действителният INSTREAM код на приложението. Default integration тестът използва fake scanner; отделният явен real-ClamAV lab действително е изпълнен и има отделен PASS/HOLD отчет с действително обновени сигнатури.

V14 създава **schema/config 2** с offline lifecycle guard. Няма upgrade на стар store. Реалният Linux scanner тест е в `REAL_CLAMAV_REPORT_BG.md`; signature freshness е преминала в отделния v13 lab; актуалността трябва да се проверява отново при следващо използване. Пълният backup е в `CANDIDATE_BACKUP_BG.md`.

## 1. Зависимости

Разархивирай v14 отделно от всички предишни версии. Отвори terminal в `PatientPortal-FastTrack-v14`. Venv и data директорията остават **извън проекта**.

Linux — командите са изпитани с Python 3.12:

```bash
python -m venv ../PatientPortal-v14-venv
../PatientPortal-v14-venv/bin/python -m pip install -r TEST_ENV_VERSIONS.txt
../PatientPortal-v14-venv/bin/python -B tools/run_candidate.py init --data-dir ../PatientPortal-v14-data --confirm-synthetic-only
../PatientPortal-v14-venv/bin/python -B tools/run_candidate.py check --data-dir ../PatientPortal-v14-data
../PatientPortal-v14-venv/bin/python -B tools/run_candidate.py serve --data-dir ../PatientPortal-v14-data
```

Windows — обикновен PowerShell, без Administrator; тези Windows команди и OS locking не са изпитани в текущата Linux среда:

```powershell
py -3 -m venv ..\PatientPortal-v14-venv
& ..\PatientPortal-v14-venv\Scripts\python.exe -m pip install -r .\TEST_ENV_VERSIONS.txt
& ..\PatientPortal-v14-venv\Scripts\python.exe -B .\tools\run_candidate.py init --data-dir ..\PatientPortal-v14-data --confirm-synthetic-only
& ..\PatientPortal-v14-venv\Scripts\python.exe -B .\tools\run_candidate.py check --data-dir ..\PatientPortal-v14-data
& ..\PatientPortal-v14-venv\Scripts\python.exe -B .\tools\run_candidate.py serve --data-dir ..\PatientPortal-v14-data
```

Сървърът слуша само на `127.0.0.1`, default port 8000, с 2 workers (може `--workers 1` и друг `--port`). Няма опция за публичен host, proxy trust или deployment. Отвори `/login` на този локален сървър от същата машина. В облачната onboarding среда localhost не е потребителски preview. Спиране: Ctrl+C на собствения terminal; няма Windows service/firewall промени.

## 2. Синтетичните акаунти

`init` генерира случаен служебен акаунт и два тестови пациентски акаунта. Потребителските имена и пароли са в **локалния** файл `../PatientPortal-v14-data/synthetic-accounts.json`. Не се отпечатват в логовете и не са включени в ZIP. На POSIX директорията е 0700, генерираните secret/account файлове са 0600; Windows ACL изисква отделна проверка. Не копирай файловете в проекта или chat.

UI показва „ТЕСТОВ КАНДИДАТ v1.14 · Само синтетични данни · HOLD / NO-GO“. Предварително генерираният legacy PDF е публикуван синтетичен пример **без AV атестат**, затова достъпът до самия файл е задържан с 423 до изричен служебен scan.

## 3. Scanner и работен ред

Нормалният кандидат винаги използва `clamd` на **127.0.0.1:3310**; друг локален порт се задава при `init --scanner-port PORT`. Няма scanner-off или fake-clean режим в launcher-а. Отделният real-ClamAV lab използва собствен временен контейнер; той е премахнат след проверките. Няма автоматично инсталиране или пускане на scanner при serve.

Login/UI могат да работят без daemon; upload и rescan тогава отказват с 503. За реално качване в изолираната кандидат-инсталация е нужен отделно подготвен и проверен локален ClamAV. Следвай `CLAMAV_OPERATIONS_BG.md`; signature recency/authenticity, listener lockdown и log privacy остават независими operational проверки. Не насочвай кандидата към реални данни.

Работният ред е:

1. Вход като synthetic staff; отвори тестовия пациент.
2. Качи **генериран тестов** PDF → INSTREAM scan → непубликувана чернова с hash и AV запис в една транзакция.
3. „Преглед“ → потвърждение на правилния пациент → „Публикувай“.
4. Вход като owner synthetic patient → преглед/изтегляне. Другият пациент получава 404.
5. За първоначалния legacy пример: „Провери с антивирус“. Outage/FOUND/error оставят hold; clean scan на точните байтове позволява достъп. Няма автоматично изтриване/оттегляне.

## 4. Повторно стартиране

Изпълнявай само `serve` отново със същата data директория. Не повтаряй `init`: то отказва всяка съществуваща директория, без overwrite/reset/reseed. Съхраняват се candidate-secret, акаунти, сесии, AV атестати и документите. Не подменяй lock state при живи workers. Няма upgrade на v6/v7/v8/v9 DB в тази команда.

`check` проверява локалната versioned schema/marker/lock state, **не** scanner наличност или production readiness. При повреден/unprepared store, production mode, променен release gate или липсващи slots стартът отказва; няма тихо възстановяване или backfill. Legacy `portal:app` не може да отвори managed candidate DB без валидирания entrypoint. Guard-ът предотвратява случаен грешен старт, не злонамерен admin.

## 5. Граници на етапа

HTTP/не-Secure cookies са само за loopback synthetic кандидат. Няма публичен HTTPS deployment, production MFA/ACL/BitLocker, реален scanner/signature review, независим restore/security/GDPR sign-off или Windows installer. `app/production_check.py` и `app/manage.py` са запазени legacy инструменти; **не ги използвай за инициализация на този кандидат**. Каноничният път е `tools/run_candidate.py`.

Преди реални пациенти е необходим отделен одобрен deployment/migration план и независима проверка. **HOLD / NO-GO остава.**
