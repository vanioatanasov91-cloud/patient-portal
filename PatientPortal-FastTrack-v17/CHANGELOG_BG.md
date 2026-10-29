# Fast Track17

- Записани са точните потребителски Windows ClamAV/PDF резултати, без превръщане в независимо одобрение.
- Добавени са три Windows launchers за encrypted backup, restore в отделна папка и проверка наlocalhost8001 със съществуващия FastTrack15 venv/data.
- Read-only candidate SQLite връзките се затварят изрично при успех/грешка; оригиналните данни и crypto форматът се пазят.
- Запазени са всички18 тестови групи и предишните тестови файлове; добавени11 desktop backup/drill случая към група18.
- Само синтетични данни. Native Windows backup/drill предстои; HOLD / NO-GO остава.

# Fast Track 16 — portable Windows ClamAV без Docker

- Standalone START_CLAMAV_WINDOWS.cmd/CHECK_CLAMAV_WINDOWS.cmd + stdlib helper; fixed official Windows64 1.5.4 package URL/size/SHA, safe selective runtime extraction/hash, own LOCALAPPDATA scanner root/lock.
- Offline immutable CVD snapshots, native sigtool signatures, UTC0/48h/clean/EICAR preflight, loopback3310, owned foreground shutdown, no system service/registry/firewall/portal data changes or unrelated process kill.
- Small companion ZIP works with current running15portal. Full16 keeps existing own desktop15 data/schema1 and candidate2; all BG functionality/schema/AV/shared/backup preserved.
- 18 regression groups preserved; group12 adds12 portable guard cases. Official package hash/extraction/PE x64 checked in Linux, native Windows execution still pending user confirmation. HOLD / NO-GO remains.

# Fast Track 15 — по-лесно локално Windows стартиране

- START_WINDOWS.cmd/CHECK_WINDOWS.cmd: explicit Python3.13→3.12, source-relative launch, без default3.15/system32 зависимости, read-only diagnostics.
- Stdlib desktop bootstrap: own versioned LOCALAPPDATA store/venv, no adoption/reset, source/dependency/native-exit checks, singleton lock, browser after HTTP readiness, controlled own-process shutdown.
- Нов optional candidate --require-fresh-scanner включва per-upload/rescan48h guard за desktop; normal defaults/schema2/AV/shared/backup са запазени. Login/UI/branding са достъпни без scanner, PDF остава fail-closed.
- Group17 добавя9 desktop cases към original42/8pilot; общите groups остават18. Pip Windows64/CPython3.13 wheel resolution е отделна проверка. Native Windows изпълнение не е потвърдено от Linux тестовете.
- BG UI label v1.15, Windows setup/branding/scanner handoff. Няма Python/ClamAV/OS service install,real data migration или независим approval; HOLD / NO-GO остава.

# Fast Track 14 — работещ local Linux synthetic пилот

- Нов explicit init/serve/status/offline refresh с private persistent candidate, immutable verified CVD snapshots и labelled owned Docker scanner; loopback only, foreground, без OS service.
- Startup CVD/clean/EICAR/48h preflight и per-upload/rescan readiness hook; scanner outage/stale/future/malformed →503, supervisor cleanup. Не се оттеглят тихо вече атестирани PDF.
- OS/lifecycle locks отказват concurrent serve/refresh/backup; offline marker switch след verified update, hourly retry guard, no overwrite/adoption/migration. Коригиран restart port check за TIME_WAIT при запазен отказ на active listener.
- Запазени18 regression групи; group17 включва original42 candidate assertions и8 pilot cases. Real acceptance за normal flow,32 clients и encrypted backup/restore/restart е отделен explicit test.
- BG UI label v1.14; нормалните workflows/schema2/AV/shared/backup са запазени. Няма real data/Windows/public deployment или независим approval; HOLD / NO-GO остава.

# Fast Track 13 — действително успешно ClamAV обновяване

- Official FreshClam: daily28164 → 28168, verified CVD digital signatures, live 48 h preflight и 28 normal workflow checks PASS/HOLD.
- Поправен прекалено строг generic HEAD403 precheck: един непроменен FreshClam опит през същия proxy; CONNECT403/TLS/429/redirect и updater failure продължават да отказват. Няма spoofing, unofficial mirror, fallback или lowered freshness.
- Добавени 2 mock regression случая към съществуващите 9 update теста; общите regression групи остават 18. Backend/schema/backup са запазени; BG candidate label v1.13.
- Актуализирани actual reports и конкретна synthetic пилотна процедура. Няма real install/service/data промяна или премахване на HOLD / NO-GO.

# Fast Track 12 — изричен FreshClam update път

- Добавен временен official FreshClam snapshot → offline CVD verification → read-only scanner mount → неизменен 48 h preflight. Няма live DB update/host service/network bypass.
- Отделен sanitized update report и fail-closed отказ при HTTP403/TLS/updater/подпис. Owned container/network/anonymous volume cleanup.
- 18-те regression групи са запазени; група 12 изпълнява стария файл без редакции + 9 updater mock теста. Backend/schema/backup/URLs не са променени; UI label е v1.12.
- Реалният update е BLOCKED/HOLD при CONNECT403. Няма успешно обновени сигнатури/production approval. Предишните версии остават.

# Fast Track 11 — 28.10.2026

- Изпълнен реален official ClamAV Docker lab: verified CVD signatures, clean/EICAR/embedded-PDF detection, истински candidate upload/publish/download, daemon stop/recovery и encrypted restored startup. 28 функционални PASS.
- Daily freshness не мина (>48h); official update host получава network-policy HTTP 403. Записан domain draft, без runtime apply/publish. Статус FUNCTIONAL_PASS/FRESHNESS_HOLD, exit 1.
- Добавен пълен offline encrypted candidate backup с marker/secret/generated accounts и authenticated new-directory restore. Shared lifecycle guard в supervisor/всеки worker отказва backup на жив кандидат.
- Fresh candidate schema/config 2; няма upgrade/overwrite на v10 или реални данни. Старите 17 test source групи са запазени; добавена 1 offline backup група, общо 18.
- Няма scanner host/Windows service, firewall/ACL/BitLocker промяна, production deployment или независим approval. HOLD / NO-GO остава.

## История

# Fast Track 10 — 28.10.2026

- Реализиран нормален synthetic кандидат: `tools/run_candidate.py init/check/serve`, автоматично включени AV hold и shared admission от candidate entrypoint. Няма test-only worker injection в този път.
- Нова изолирана versioned schema с Report FK и CHECK constraints за AV records; инициализация само в несъществуваща data директория. Read-only startup preflight, отказ при неправилен entrypoint/missing state, без overwrite/reseed/backfill.
- Случайни synthetic акаунти, постоянен local candidate secret, UI/HOLD банер и запазване на акаунти/сесии/AV evidence след рестарт.
- Всички предишни 16 групи са запазени. Добавена 1 shipping CLI/нормален workflow/restart група: общо 17. Само synthetic данни; INSTREAM protocol daemon е фалшив.
- Промените в portal.py са ограничени до startup guard. AV policy има table binding и запазен compatibility alias. Българският интерфейс и съществуващите URL/workflow-и са запазени.
- Няма реална инсталация, реален scanner/production migration или approval. HOLD / NO-GO остава.

## История

# Fast Track 9 — 28.10.2026

- Нов shared PDF admission модул за една машина: OS lock slots общи между workers; нормално/crash recovery, fail-closed при shared state failure. Активира се само изрично в synthetic fixtures.
- Pure ASGI ingress преди multipart parsing: общ/upload лимит, Content-Length и byte counting, body receive deadlines, cleanup на частични spools. Slot-ът остава зает при cancellation до завършване на вътрешната работа.
- Нов boundary/resource harness с 2 собствени локални workers: 15 MiB upload, 64 MiB legacy download, +1 byte откази, бавен mocked scan/outage, HTTP disconnect, 30 s bounded soak и sampled RSS/CPU budgets.
- app/portal.py, v8 AV модулът, българските templates/CSS/JS и всички предишни 13 групи са запазени. Добавени 3 групи: общо 16.
- Няма реален scanner, production DB/proxy/OS/Windows промени или release approval. HOLD / NO-GO остава.

## История

# Fast Track 8 — 28.10.2026

- Запазен v7 baseline: 10/10 групи преди промени.
- Добавен fixture-only AV attestation/hold прототип и staff/CSRF rescan с български указания. Без production migration/backfill, автоматично оттегляне/изтриване или default legacy промяна.
- Затегнат clamd zINSTREAM parser: непълен OK е отказ, общ scan deadline; добавен operator-only preflight с mocked tests.
- Изолиран HTTP harness с 2 workers и 32 заявки, временно генерирани пациенти/PDF/SQLite и latency/RSS отчет. Не е production капацитетна оценка.
- Оригиналните 10 групи са запазени; добавени 3 нови. Подробните действителни резултати са в TEST_REPORT_BG.md.
- Актуализирани SHA256 манифести и handoff документация. HOLD / NO-GO не е променен.

## История

# Fast Track 7 — промени спрямо Fast Track 6

1. **Преминаване към Codex**: добавени `AGENTS.md` и `CODEX_START_HERE_BG.md` с правила за безопасно развитие и copy-paste prompt.
2. **Read-only legacy inventory**: добавен `tools/legacy_pdf_inventory.py`, проверяващ единствено офлайн копие и извеждащ агрегирани метрики, без файлове/хешове/пациентски полета в резултата.
3. **Нови синтетични тестове**: legacy integrity / unsafe path / missing hash и in-process concurrent PDF delivery (16 кандидата, капацитет 2).
4. **Общ runner**: разширен от 8 на 10 offline групи, с доклад и задължителен `HOLD / NO-GO`.
5. **Windows PowerShell**: безопасно откриване на Python извън проекта, включително стария успешен v6 тестов Python и v7-venv.
6. **Без промяна** на приложението, работните потоци, маршрути, HTML/CSS/JS, базата данни, Windows услугите и продукционните файлове. Реален AV преглед, legacy hold политика и multi-worker stress test предстоят.

Корекцията затваря изрично и новосъздадената lifecycle SQLite връзка след commit, преди преименуване на възстановената директория. Проверен е и запазеният marker след затварянето.
