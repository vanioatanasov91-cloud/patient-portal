# Fast Track 15 — текуща оценка

Решени са конкретните user setup грешки: Python3.13 е наличен, default3.15 не се избира; START_WINDOWS.cmd използва своята папка и спира при липсващ ZIP source/native failure. Persistent own desktop root пази sessions/data между launches без reinit/adoption. Existing v14 stores не се променят.

Native Windows/CMD/GUI/ACL/multiprocessing не могат да се удостоверят в текущата Linux среда. Проверени са stdlib bootstrap/реален localhost HTTP и per-scan freshness CLI option, plus Windows64/3.13 wheel resolution. Actual suite/report е TEST_REPORT_BG.md. Няма auto ClamAV/Python/service/OS policy provisioning, реални данни или independent approval. HOLD / NO-GO остава.

# Fast Track 14 — текуща оценка

Преминато е от временен scanner lab към foreground Linux pilot с persistent synthetic data и собствен localhost ClamAV. Основният backend има само nullable scanner_precheck hook (3 lines); candidate_runtime приема explicit precheck, който pilot_entry включва. Старите candidate/legacy entrypoints не променят поведението си.

Per-scan VERSION/UTC/48h е operational check, не криптографска provenance гаранция срещу привилегирован admin. CVD signing/hash и strict file allowlist се проверяват при initialization/update/startup; readiness не заменя независим review. Pilot root/schema1 е отделен от candidate schema2. Refresh е offline с immutable snapshots и OS/lifecycle guards. Snapshot freshness не е auto-update услуга; операторът планира explicit daily maintenance.

Има local foreground пилот в наличната Linux среда, не Windows/HTTPS/public preview. Actual evidence е в PILOT_REPORT_BG.md/TEST_REPORT_BG.md. Само synthetic данни; няма real migration/install/service промяна. HOLD / NO-GO остава.

# Fast Track 13 — текуща оценка

Мрежовата промяна е приложена. Generic HEAD403 не е достатъчно доказателство, че real FreshClam е блокиран: actual official client изтегли daily28168 с непроменени proxy/TLS/CVD checks. V13 допуска един истински updater опит при upstream HEAD403, но CONNECT403/TLS/429/redirect/updater failure остават отказ. Няма scanner fallback.

Actual CVD digital signatures, live 48 h preflight и 28 normal candidate workflow checks са passed; snapshot/scanner са били временни и са премахнати. Това завършва отделната update стъпка, не постоянна update deployment услуга. Backend/schema2/AV/shared/backup са непроменени; BG UI label е v1.13. Следва отделен synthetic пилот/независим review; HOLD / NO-GO остава.

# Fast Track 12 — текуща оценка

Има възпроизводим изричен update път, но няма успешно свалени свежи сигнатури: official host остава policy-blocked HTTP403. Няма scanner/candidate fallback при update failure. Full update/download/read-only updated snapshot/preflight success не са потвърдени с реален endpoint; unit тестовете за този път са mocked. Изпълнените актуални проверки са в TEST_REPORT_BG.md.

Нормалният кандидат, schema/config 2, AV hold/shared admission и encrypted backup са запазени. Българският UI променя само видимия candidate version label. Production gate остава HOLD / NO-GO. Независимата целева deployment/security/privacy/restore проверка не е заменена от локалния lab.

# Fast Track 11 — текуща оценка

- Реален ClamAV 1.5.4 / official immutable Docker image: 28 функционални проверки passed, main/daily/bytecode CVD signatures verified. Няма fake scanner в този lab.
- Signature freshness е FAILED: daily 25 Oct >48h към 28 Oct; database.clamav.net е HTTP 403 network-policy blocked. Добавеният draft domain е saved, не runtime-applied/published. Общият scanner preflight не е passed.
- Нормалният synthetic кандидат запазва workflow/UI. Нов fresh schema/config 2 добавя отделен lifecycle SQLite guard за supervisor/всеки worker срещу concurrent offline backup.
- Пълният AES-GCM/scrypt backup включва DB/PDF + marker/secret/generated accounts; restore само в нова директория с нови runtime locks. Wrong-key/tamper/overwrite/live-store са отказани; legacy API default compatibility е запазена.
- Няма real-data migration, system scanner/service/firewall/ACL или Windows/HTTPS deployment. HOLD / NO-GO остава.

## История

# Fast Track 10 — текущ резултат

- Преминато е от fixture-only hooks към нормален `init/check/serve` път за нов синтетичен кандидат. AV/shared слоевете са включени автоматично от candidate entrypoint.
- Няма upgrade на стара/реална DB. Versioned fresh schema, FK/CHECK constraints, read-only preflight и legacy-entrypoint bypass guard ограничават грешната употреба.
- Установените workflow-и, URLs и български UI са запазени; добавен е видим candidate/HOLD банер.
- Интеграционната група използва доставяните команди и истински HTTP/INSTREAM клиент, но фалшив loopback daemon. Реален scanner/signatures/security/GDPR/Windows deployment остава независимо непроверен.
- Кодът е стартиращ локален synthetic кандидат, не production installer/approval. HOLD / NO-GO остава.

## Историческа оценка

# Fast Track 9 — текуща оценка

- Запазени v8 backend, всички templates/CSS/JS, AV policy модул и предишните 13 групи.
- Нов fixture-only pure ASGI shared admission обхваща PDF upload/delivery/publish/scan преди parser и до приключване на вътрешната работа. Файлови OS locks са проверени между отделни процеси, включително abrupt exit.
- Добавени body size/deadline и реален parser cleanup, плюс cancellation draining; няма default production activation.
- Новата HTTP група проверява 15 MiB uploads / 64 MiB legacy delivery, +1 byte откази, бавен fake scanner/outage, disconnect и bounded 30 s soak с sampled CPU/RSS budgets.
- Това е Linux single-host тест, не Windows/NFS/SMB/много host-ове или production capacity доказателство. Няма реален scanner/proxy/OS настройки или промяна на реални данни.
- Остава HOLD / NO-GO; виж текущите TEST_REPORT_BG.md, SHARED_ADMISSION_BG.md и RESOURCE_POLICY_BG.md.

## Историческа оценка за v8/v7

# Fast Track 8 — текуща оценка

- Оригиналните 10 групи бяха изпълнени успешно преди редакциите (baseline v7).
- V8 добавя явен synthetic AV policy hook и служебен rescan, без default legacy промяна, production schema update или backfill. Подробно: `LEGACY_AV_DESIGN_BG.md`.
- Upload clamd parser вече отказва truncated OK; има общ deadline. Preflight е operator-only, автоматичните проверки са mocked.
- Има реален HTTP smoke срещу собствен временен server с 2 workers и 32 конкурентни заявки. Няма реален scanner, големи payload capacity/soak или shared admission гаранция.
- Съществуващите security/privacy/deployment ограничения важат; HOLD / NO-GO остава.

## Историческа оценка за v7

# Fast Track 7 — обхват, независими граници и рискове

- V7 наследява Fast Track 6 **без промяна на `app/portal.py`** и без DB миграция или промяна на HTML/CSS/JS.
- Изолиран read-only инвентаризационен инструмент проверява само контейнерни признаци, SHA-256 и съществуване на файлове на **OFFLINE копие**, без да добавя вирусни атестати. Този инструмент не е безопасна автоматична миграция и не решава политика за legacy документите.
- Новата конкурентна проверка използва 16 синтетични нишки и фалшиво ASGI изпращане за **per-process** semaphore; не измерва throughput, RAM/CPU, много worker-и, обратен proxy или реални HTTP клиенти.
- Старите 8 групи проверяват код, UI, synthetic DR, access, PDF, snapshot, admission и фалшив clamd socket.
- Няма инсталиран/тестван реален clamd daemon, външен scanner, политика за подписите, реален penetration test, Windows ACL/BitLocker review или DPIA.
- `PORTAL_PDF_SCAN_MODE=off` в development не предоставя защита от malware. Production стартирането изисква режим `clamd`, но само настройката не доказва наличност/качество на скенера.
- За реална употреба остава `RELEASE GATE: HOLD / NO-GO` до независима оценка и операторско одобрение.
