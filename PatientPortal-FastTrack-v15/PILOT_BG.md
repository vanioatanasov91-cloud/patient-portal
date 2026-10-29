# Fast Track 14 — работещ Linux synthetic пилот

**HOLD / NO-GO. Само синтетични данни, без production activation.**

## Среда и подготовка

Наличната облачна среда е Linux/UID1000 с локален managed Docker socket. Pilot CLI е ограничен до този профил; Windows/HTTPS/service/ACL/BitLocker изискват отделна целева среда и изрична operator процедура. Не са приложени firewall/proxy/OS policy промени. В managed cloud следвай runtime Docker/proxy/CA инструкциите. Образът трябва вече да е наличен отделно; init не pull-ва:

```text
clamav/clamav@sha256:bda39705e291105049c3936e2803ac90b955172af8030f94f05dce1252df6c6d
```

Source, venv и pilot data са отделни. С изолирания venv от CANDIDATE_START_BG.md:

```bash
python -B tools/run_pilot.py init --pilot-dir ../PatientPortal-pilot-v14 --confirm-isolated-synthetic-pilot
python -B tools/run_pilot.py serve --pilot-dir ../PatientPortal-pilot-v14
```

Init изисква нова несъществуваща директория извън всички source releases. Създава нов synthetic candidate/schema2, private pilot metadata/schema1 и fixed lifecycle/OS locks. Прави един official FreshClam update в нов snapshot с непроменени proxy/TLS/CVD проверки. Няма copy/import на стари данни, повторен seed, overwrite или migration. Ако update откаже, store-ът е awaiting_signatures; след поне1h може да се възобнови с refresh. Не повтаряй init върху него.

## Пускане и достъп

Serve е **foreground**, работи докато неговият процес/облачната среда са активни. Не е инсталирана OS услуга, автоматичен boot/restart или публичен deployment. Управлява labelled own Docker bridge/scanner и normal pilot entrypoint с2 HTTP workers. Scannerът е non-root/read-only/cap-drop/no-new-privileges, 2GiB/2CPU/pids64, без candidate DB/PDF mounts. Config/CVD се монтират read-only. На host се публикува само loopback.

От **същата машина** отвори http://127.0.0.1:18080/login. В cloud localhost не е линк за браузъра на потребителя. За външен достъп е нужна отделна одобрена access/HTTPS процедура; текущата версия не отваря public порт.

Случайните synthetic credentials са само в локалния private `pilot-dir/candidate/synthetic-accounts.json` (0600, parent0700). Не ги копирай в chat/лог/ZIP. Използвай служебния акаунт и двата тестови пациентски акаунта. Българският интерфейс/URL/workflow са запазени. След acceptance пилотът съдържа генериран публикуван пример и изрично проверен legacy пример.

```bash
python -B tools/run_pilot.py status --pilot-dir ../PatientPortal-pilot-v14
```

Status е sanitized JSON без secrets; exit0 означава active pilot lock + достъпен login + fresh localhost scanner. Не е production approval. Startup допълнително верифицира digital signatures и изпълнява real clean/EICAR preflight. Всеки upload/rescan прави нов bounded VERSION/48h check; outage/stale/future/malformed отказват с503 преди INSTREAM. Вече атестирани документи не се оттеглят тихо. Супервизорът спира своите процеси/контейнер при загуба на готовност.

## Спиране, рестарт, обновяване

Спиране: Ctrl+C на собствения serve terminal. Запазват се marker, candidate DB/secret/accounts/PDF/AV evidence и CVD snapshots. Премахват се само собствените labelled Docker resources и owned child processes. Не се чете PID от файл за kill, не се спират чужди services. След това serve отново със същата pilot-dir запазва sessions/документи; не повтаряй init и не подменяй locks.

Няма скрит автоматичен download timer. Обновяването е **изрична offline операция**, поне1h между опитите; за продължителен пилот операторът го планира ежедневно. Старият mounted snapshot не се променя при жив scanner/worker. Stop → refresh → serve:

```bash
python -B tools/run_pilot.py refresh --pilot-dir ../PatientPortal-pilot-v14 --confirm-offline-synthetic-pilot
python -B tools/run_pilot.py serve --pilot-dir ../PatientPortal-pilot-v14
```

Pilot OS lock и candidate exclusive lifecycle guard отказват refresh при жив supervisor или standalone normal workers. Новият snapshot се проверява offline и marker се сменя атомично едва след успех; при update failure предишният verified snapshot остава. Serve все пак изисква текущ 48h preflight. Автоматичен freshness bypass/off/fake-clean режим няма.

## Backup/restore и независимо наблюдение

След stop следвай CANDIDATE_BACKUP_BG.md към **pilot-dir/candidate**. Archive output трябва да е извън candidate; restore само в нова директория. Candidate backup пази DB/PDF/identity/accounts/AV evidence, а не Docker/runtime state/CVD snapshots. Restore е normal synthetic candidate с нови locks; за управляван пилот на друга машина е нужна отделна подготовка на scanner/config, без adoption на real store. Не подменяй текущия pilot candidate с restore.

Първоначалният unused pilot може изрично да изпълни real acceptance без нов update:

```bash
python -B tools/pilot_acceptance.py --pilot-dir ../PatientPortal-pilot-v14 --confirm-synthetic-pilot-exercise
```

Изпълнява се при спрян пилот и точно началния synthetic state (1 legacy report/0 AV attempts); не reset-ва/reseed-ва, ако вече е използван. Стартира/спира само собствени supervisors, проверява normal staff/patient/other flow, EICAR,32 concurrent requests/shared limits и encrypted offline backup/restore/restart; оставя първичните synthetic reports за преглед, премахва временните restore/archive copies. След това serve отново за ръчно използване. Това е Codex acceptance, **не независимо одобрение**.

Независимият reviewer трябва да запише действителна дата/ОС/version/hash, резултати за достъп, scanner/update/restore/provenance/privacy/retention, ограничения и нерешени проблеми. Няма измислен reviewer/sign-off. Windows/HTTPS/ACL/BitLocker/GDPR/DPIA/дълъг capacity и реална миграция остават преди реални пациенти. **HOLD / NO-GO остава.**
