# Fast Track 16 — действителен отчет

**HOLD / NO-GO. Само синтетични данни. Няма независимо одобрение за реална употреба.**

## Резултат от тестовете

`python -B tools/fasttrack_runner.py --include-synthetic` → **18/18 PASS**. Всички планирани групи са изпълнени. Отчет: 29.10.2026 20:34:39 EET; Linux/Python 3.12.14. Машинният отчет е `reports/last_fasttrack_run.json`.

| Група | Резултат | Секунди |
| --- | --- | --- |
| static | PASS | 0.115 |
| dr | PASS | 0.501 |
| ui | PASS | 1.637 |
| security | PASS | 1.85 |
| pdf | PASS | 1.19 |
| snapshot | PASS | 1.227 |
| admission | PASS | 1.172 |
| scan | PASS | 1.844 |
| legacy_inventory | PASS | 0.137 |
| concurrency | PASS | 0.814 |
| legacy_policy_v8 | PASS | 0.972 |
| clamd_preflight_v8 | PASS | 0.93 |
| http_load_v8 | PASS | 2.204 |
| shared_admission_v9 | PASS | 0.447 |
| ingress_v9 | PASS | 0.333 |
| resource_load_v9 | PASS | 34.619 |
| candidate_workflow_v10 | PASS | 19.828 |
| candidate_backup_v11 | PASS | 4.731 |

Всички предишни тестови файлове са запазени без промяна. Група12 първо изпълнява старите24 проверки за clamd и11 случая за обновяване, после12 нови случая за преносимия скенер. Те покриват повредено изтегляне, ограничен официален адрес, опасни ZIP пътища/връзки, нужните runtime/certificate/license файлове, отказ на неподписан CVD,48h/бъдещи дати, зает порт, заключване на собствената папка и неуспешно обновяване без замяна на стария snapshot. Използват се изрично синтетични PE/CVD образци; Windows EXE не се изпълняват от тестовете.

Група17 пази42 първоначални candidate проверки,8 pilot случая и9 desktop случая. Проверени са и наследените PDF ограничения, достъп/публикуване,32 едновременни HTTP клиента,2 работни процеса,30-секундно ограничено натоварване и криптирано архивиране/възстановяване. Това не е удостоверяване на капацитет за реална инсталация.

## Проверка на официалния Windows пакет

Реално изтегленият Cisco-Talos ClamAV1.5.4 Windows x64 ZIP е **225774978 bytes**, SHA256 `0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395`, съвпадащ с публикувания release digest. Новата функция за безопасно извличане е изпълнена върху този ZIP в Linux: избрани48 файла,134807894 bytes, включително clamd/freshclam/sigtool, runtime DLL, сертификатите за CVD и лицензите. Големите debug файлове не се извличат. Трите основни EXE имат очакваните AMD64 PE headers. Отчет: `reports/windows_clamav_package_check.json`.

Това е проверка на целостта, структурата и извличането. **Native Windows EXE/DLL loading, FreshClam download, CVD signature verification и реалният Windows clamd/preflight/PDF upload НЕ са изпълнени тук.** Няма Authenticode/GPG или независимо production одобрение. При първото пускане на целевия Windows компютър добавката изисква native sigtool verification и PING/clean/EICAR/48h проверка, преди да покаже готовност. EICAR контролът е само в паметта и е безвреден.

Потребителят потвърди само успешния вход и страницата с настройки на портала v1.15 чрез screenshot. Това не доказва работещ Windows скенер. Старите Linux ClamAV/pilot отчети са исторически и не се представят като нови Windows резултати. Докладът за31 Windows/Python3.13 wheels също е наследен от v15.

## Обхват на промяната

Новият отделен scanner ZIP съдържа2 CMD файла,2 Python инструмента, инструкция и SHA256 списък. Няма EXE/DLL/CVD, пароли, PDF, ключове или база на портала. Работи до вече стартирания v15, без да чете/променя неговите данни, потребители или настройки. Не е нужно повторно стартиране/инициализиране на портала. Backend `portal.py`, всички предишни тестове и `desktop_start.py` са запазени без промяна. Пълният v16 source сменя само етикета на интерфейса и добавя инструментите/документацията/тестовия entrypoint; съвместимите desktop15/candidate2 формати остават.

Scanner-ът ползва собствена LOCALAPPDATA папка и foreground процес на127.0.0.1:3310. Проверката за свободен порт използва SO_EXCLUSIVEADDRUSE в Windows; SO_REUSEADDR е само за Linux тестовете. Windows услугите, Docker, firewall, registry, ACL, глобалният PATH и системният часовник не се променят. Snapshot обновяването е отделно от работещия скенер; при неуспех няма ready/fallback. Нужни са ежедневно изрично спиране/пускане и потвърждение на целевия компютър.

Независими Windows/deployment/security/privacy/GDPR/backup/scanner/retention и capacity проверки остават преди реални пациенти. **HOLD / NO-GO остава.**
