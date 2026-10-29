> V14 pilot: update_snapshot се използва при init/explicit offline refresh за постоянен private synthetic store; snapshot не се променя live. Procedure: PILOT_BG.md. Следва историческият V13 временен lab.

# Fast Track 13 — успешно изолирано FreshClam обновяване

**HOLD / NO-GO. Само синтетичен кандидат и собствени временни Linux Docker ресурси.**

## Действителен резултат

Environment network промяната е приложена: observations_current true, policy unrestricted/enforced, observed revision 3. Старият CONNECT403 вече отсъства. Generic HEAD до official endpoint връща HTTP403, но непромененият official FreshClam клиент успява през същия proxy/TLS. V12 спираше прекалено рано на този HEAD отказ. V13 го записва като диагностика и допуска един реален updater опит; не променя User-Agent, mirror или trust настройки. CONNECT403, TLS failure, HEAD429 и redirect продължават да спират преди Docker.

FreshClam обнови daily **28164 → 28168**, digital signatures на main/daily/bytecode са verified. New daily build: **29 октомври 2026, 08:24:16 ч. (Europe/Sofia)** / 06:24:16 UTC. SHA256: `78f0db96691a7194f15790a60bdbc496068df38e7d55db9fe41ccc18a04c765d`.

Live clamd VERSION е ClamAV 1.5.4/28168; PING, clean INSTREAM, EICAR rejection и 48 h freshness са true. Всички **28 функционални проверки** на normal candidate с два workers минаха: clean PDF → preview/publish/owner download, embedded EICAR refusal/cleanup, stop/outage/recovery, legacy rescan и encrypted backup/restore със запазени session/AV evidence. Exit **0**, **PASS/HOLD**, cleanup_completed true. Точните времена/metadata са в reports/last_signature_update.json; reports/last_real_clamav_check.json е същият текущ real lab резултат. Историята на предишните откази е в baseline_v12_*.

## Повторение

Нужен е управляван Linux Docker daemon и отделно наличен official immutable образ:

```text
clamav/clamav@sha256:bda39705e291105049c3936e2803ac90b955172af8030f94f05dce1252df6c6d
```

```bash
python -B tools/real_clamav_candidate_check.py --confirm-isolated-real-scanner-test --update-signatures
```

Командата не pull-ва образ, няма произволен target URL/output directory, не пипа работещ scanner или реален store. Новият private snapshot се seed-ва от official image и проверява offline със sigtool. FreshClam прави един update с official DatabaseMirror, --no-dns, ScriptedUpdates no, TestDatabases yes, без daemon/NotifyClamd/hooks. Пълните подписани CVD позволяват независима sigtool проверка; това е еднократен lab, не препоръчана честа production download политика.

Updater-ът пази наследените Docker proxy defaults и read-only публичния комбиниран CA bundle чрез CURL_CA_BUNDLE. Root FS е read-only, UID/GID1000, cap-drop ALL, no-new-privileges, 2 GiB/2 CPU/pids64, tmpfs. Пише само в собствен snapshot. След update всяко CVD отново се верифицира, hash-ва и се отказват unsigned/неочаквани допълнителни DB файлове. Scanner-ът получава само read-only config/signature mounts, без candidate DB/PDF mounts. Host port е само 127.0.0.1.

При updater/подпис/48 h failure няма fallback към старите image бази. Raw proxy/updater output не се публикува. Собствените контейнери/anonymous volumes/network и temp данните се премахват. Default suite остава offline/mocked.

## Практическа граница

Успешният snapshot е **временен** и не е инсталиран в постоянен кандидат. След lab-а scanner-ът е премахнат. Няма непрекъсната update/monitoring услуга, Windows service, HTTPS/ACL/BitLocker или независим review. Freshness PASS важи в момента на изпълнение и трябва да се проверява отново. **HOLD / NO-GO остава.**
