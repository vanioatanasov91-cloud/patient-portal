# Fast Track 15 — действителен отчет

**HOLD / NO-GO. Само synthetic данни; няма production approval или native Windows sign-off.**

## Default regression suite

`python -B tools/fasttrack_runner.py --include-synthetic` → **18/18 PASS**, всички планирани групи изпълнени. Отчет: 29.10.2026 19:25:21 EET. Текущата execution среда е Linux/Python3.12.14; Windows не е наличен. Няма нови host packages/OS services.

| Група | Резултат | Секунди |
| --- | --- | --- |
| static | PASS | 0.122 |
| dr | PASS | 0.547 |
| ui | PASS | 1.83 |
| security | PASS | 2.004 |
| pdf | PASS | 1.284 |
| snapshot | PASS | 1.189 |
| admission | PASS | 1.244 |
| scan | PASS | 1.705 |
| legacy_inventory | PASS | 0.132 |
| concurrency | PASS | 0.922 |
| legacy_policy_v8 | PASS | 1.164 |
| clamd_preflight_v8 | PASS | 1.018 |
| http_load_v8 | PASS | 2.985 |
| shared_admission_v9 | PASS | 0.566 |
| ingress_v9 | PASS | 0.411 |
| resource_load_v9 | PASS | 35.181 |
| candidate_workflow_v10 | PASS | 21.418 |
| candidate_backup_v11 | PASS | 4.667 |

Всички предишни test source файлове са byte-for-byte запазени. Group17 първо изпълнява original42 candidate assertions и8 pilot cases, после **9 desktop bootstrap случая**: native nonzero exit stops progression, pip failure без data init, existing data/session identity без reseed, credential-free diagnostics, unknown/source/production root refusal, singleton/gate guard, read-only no-write checks, foreign8000 listener refusal и browser-after-real-HTTP readiness с explicit freshness flag. Старата suite не е replaced/skipped; новият тест не отваря native browser и не инсталира/сваля dependencies.

Bootstrap HTTP integration използва истински shipping run_candidate.py serve,2 workers и localhost fake scanner. При stale VERSION upload е503 преди INSTREAM, при fresh VERSION е303; browser callback се извиква след HTTP200, собствените процеси приключват контролирано. Това е реален Linux HTTP тест на преносимата логика, не Windows multiprocessing доказателство.

## Windows64/Python3.13 dependency resolution

Отделен pip --dry-run --ignore-installed --only-binary=:all: --platform win_amd64 --python-version3.13 --implementation cp --abi cp313 разреши всичките **31** фиксирани requirements като wheel файлове. Нищо не е инсталирано в host или потребителски Windows. TLS/proxy trust са запазени. Sanitized evidence: reports/windows_dependency_resolution.json; raw pip metadata/URLs не са публикувани.

Потвърдена е наличност на Windows wheels за MarkupSafe/SQLAlchemy/argon2-cffi-bindings/cffi/charset-normalizer/cryptography/Pillow/pydantic_core и universal wheels за останалите. Това не проверява Windows DLL loading/GUI/ACL/browser association/native launcher execution.

## Реална граница на проверката

START_WINDOWS.cmd/CHECK_WINDOWS.cmd са source-reviewed UTF-8/CRLF text wrappers. Изборът е само от installed-version listing:3.13, после3.12; default3.15 не се използва. Legacy auto-install flag се изчиства само в локалния cmd scope; няма постоянни PATH/ExecutionPolicy/OS policy промени. Native CMD/Windows GUI/ACL и Windows Ctrl+Break/multiprocessing **не са изпълнени** в наличния Linux executor. Първото целево пускане остава да се потвърди от потребителя чрез START_WINDOWS.cmd и при нужда CHECK_WINDOWS.cmd.

Старите v13/v14 real ClamAV/pilot reports в ancestry са исторически доказателства за Linux. Те не означават scanner/работещ портал на Windows компютъра. V15 не е пускал нов real scanner/update lab, защото scanner/runtime не са променени. Desktop UI/login могат да се отворят без scanner; всяко PDF upload/rescan изисква local UTC clamd и48h precheck. ClamAV/Python/Docker/Windows service installation не е изпълнявана/автоматизирана.

## Scope

Backend portal.py, candidate schema/config2, AV/shared admission и encrypted backup API са непроменени. New desktop marker/schema1 и LOCALAPPDATA root са отделни. Optional --require-fresh-scanner се добавя към normal candidate serve и се използва само изрично от desktop launcher. Няма автоматично приемане/миграция/reset на стар/real store. BG UI/URLs/workflow са запазени; candidate label е v1.15. All previous release/source/test hashes са запазени и source manifests/ZIP са проверени.

След successful local Windows login: synthetic center branding през /settings и отделна concrete local ClamAV operator процедура. Независими Windows/deployment/security/privacy/GDPR/backup/scanner/retention/provenance/capacity reviews остават преди реални пациенти. **HOLD / NO-GO остава.**
