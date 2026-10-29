# Fast Track17 — действителен отчет

**HOLD / NO-GO. Само синтетични данни. Няма независимо одобрение за реални пациенти.**

## Автоматични проверки

`python -B tools/fasttrack_runner.py --include-synthetic` → **18/18 PASS**. Всички планирани групи са изпълнени. Отчет: 29.10.2026 21:50:27 EET. Среда: Linux/Python3.12.14. Машинен отчет: `reports/last_fasttrack_run.json`.

| Група | Резултат | Секунди |
| --- | --- | --- |
| static | PASS | 0.119 |
| dr | PASS | 0.492 |
| ui | PASS | 1.538 |
| security | PASS | 2.012 |
| pdf | PASS | 1.205 |
| snapshot | PASS | 1.152 |
| admission | PASS | 1.066 |
| scan | PASS | 1.6 |
| legacy_inventory | PASS | 0.145 |
| concurrency | PASS | 0.748 |
| legacy_policy_v8 | PASS | 0.925 |
| clamd_preflight_v8 | PASS | 0.889 |
| http_load_v8 | PASS | 2.537 |
| shared_admission_v9 | PASS | 0.463 |
| ingress_v9 | PASS | 0.409 |
| resource_load_v9 | PASS | 34.684 |
| candidate_workflow_v10 | PASS | 21.631 |
| candidate_backup_v11 | PASS | 13.884 |

Всички предишни тестови файлове са запазени без промяна. Група12 продължава старите scanner/updater проверки и12 portable scanner случая. Група17 продължава42 candidate проверки,8 pilot и9 desktop случая. Група18 изпълнява първо15 оригинални encrypted backup проверки и после **11 нови desktop backup/drill случая**.

Новите11 случая проверяват: отказ за непознат/липсващ desktop; действителен AES-GCM roundtrip с отделни уникални възстановени папки; отказ преди паролен prompt при desktop или worker lease; грешна парола със запазване на предишното успешно копие; променен архив/опасен index; запазване на чужда backup папка; затваряне на двете read-only SQLite връзки и връзката при неуспешна валидация, както и новосъздадената lifecycle връзка след commit; restore без оригиналната application DB; отказ за зает порт преди Popen; истински HTTP старт на възстановения store; отказ на видим getpass fallback/нетерминален input и проверка на дължина/потвърждение на паролата.

HTTP drill използва shipping `run_candidate.py serve`,2 workers, отделен loopback порт и `--require-fresh-scanner`. Browser callback се изпълнява след HTTP200. Проверени са запазено име на тестовия център, точно съвпадение на PDF bytes, restored AV fixture и owner200/other404. Накрая приключват само създадените тестови процеси. AV атестатът в този конкретен тест е изрично синтетичен fixture, не реален scanner verdict. Работещата първоначална data папка не се заменя. Това не е capacity/дълъг soak сертификат.

## Потребителска Windows проверка

Потребителят предостави screenshot с ready съобщение на native portable ClamAV16 и потвърди: legacy scan/preview без грешка; ново качване/публикуване; owner видимост/преглед/изтегляне; липса на документа и отказ на директния URL през synthetic_other. Това е отделно ръчно функционално потвърждение, получено в разговора, без прехвърляне на Windows DB/PDF/пароли/ключове. Обхватът и видът на доказателството са в WINDOWS_ACCEPTANCE_BG.md и reports/windows_user_acceptance.json. Не е независим security review или записан HTTP trace.

**Новите BACKUP_WINDOWS.cmd / RESTORE_TEST_WINDOWS.cmd / START_RESTORED_WINDOWS.cmd, getpass и native Windows restore/process cleanup НЕ са изпълнени в Linux.** Целевият ръчен backup/drill предстои. Преминалият Windows PDF сценарий не се представя като преминал Windows backup тест.

## Код и съвместимост

`app/portal.py`, предишните тестове, криптираният формат, AV/shared ограниченията, FastTrack15 desktop/schema1 и candidate/schema2 се пазят. `candidate_runtime.read_config` използва `contextlib.closing` за двете SELECT-only SQLite връзки, включително при валидационна грешка. Това освобождава Windows файловите handles преди directory rename/cleanup; няма промяна на DDL/schema или миграция. Новосъздадената lifecycle SQLite връзка също се затваря изрично след commit преди rename; тестът проверява и запазения marker.

Новият Windows helper използва съществуващия частен venv и собствените desktop/candidate маркери. Archive passphrase е само скрит TTY input, не argv/env/log. Всички имена на архиви/restore targets са уникални. Собствен SHA256 index се проверява преди decrypt; самият GCM/tag/file hash/candidate metadata се удостоверява от съществуващия API. Няма overwrite/adoption на чужда папка, auto-init/reset, спиране на чужди процеси, Windows service/firewall/registry/ACL/PATH промени или cloud качване на архива.

Source manifests и ZIP се проверяват отделно. В source/repository няма пароли, .ppbk, DB/PDF, runtime или ClamAV binaries/signature databases. Старите Linux real-scanner/pilot/package/wheel отчети са исторически, не нови Windows backup доказателства.

Независими deployment/security/privacy/GDPR/backup/scanner/retention/Windows/capacity проверки остават преди реална употреба. **HOLD / NO-GO остава.**
