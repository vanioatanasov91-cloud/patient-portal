# Patient Portal v1.14 — Fast Track 14

**HOLD / NO-GO. Само synthetic пилот; няма production approval.**

Добавен е **работещ пилотен launcher**, който запазва данните и сесиите между пусканията и управлява собствен локален ClamAV. Това е следващата стъпка след временния V13 lab. Използвана е наличната отделена Linux облачна среда, тъй като друга целева машина не е посочена.

```bash
python -B tools/run_pilot.py init --pilot-dir ../PatientPortal-pilot-v14 --confirm-isolated-synthetic-pilot
python -B tools/run_pilot.py serve --pilot-dir ../PatientPortal-pilot-v14
python -B tools/run_pilot.py status --pilot-dir ../PatientPortal-pilot-v14
```

Поддържаният pilot launcher изисква Linux/UID1000, локалния managed Docker socket и отделно наличния official pinned ClamAV image. Не е Windows installer. Старите run_candidate.py команди остават отделно запазени. Няма скрит pull или system service.

Порталът е само на 127.0.0.1:18080, scanner-ът на 127.0.0.1:13310. В облачната среда това е **localhost на executor-а, не публичен preview линк**. Акаунтите се четат само локално от частния generated файл в pilot-dir/candidate/synthetic-accounts.json; паролите не са в ZIP/chat/logs.

Startup проверява CVD цифровите подписи, PING/clean/EICAR и 48 h свежест. Всяко upload/rescan прави допълнителна VERSION/48 h проверка преди INSTREAM; при stale/future/непълен отговор/outage отказва с503. Супервизорът наблюдава scanner-а и спира само своя runtime при загуба на готовност. Данните се пазят; няма silent revoke/delete на вече атестирани документи. Подробности и offline refresh: PILOT_BG.md.

Регресионната suite остава **18 групи**, с всички стари assertions. Група17 добавя pilot guard/normal HTTP restart проверки към старите42. Real pilot acceptance е отделна изрична команда/отчет и не влиза в default offline suite. Точните actual резултати са в TEST_REPORT_BG.md и PILOT_REPORT_BG.md.

```bash
python -B tools/fasttrack_runner.py --include-synthetic
```

Българският интерфейс и workflow-и, AV hold/shared admission, schema/config2 и authenticated offline backup са запазени. Новата pilot management schema1 е отделна; няма upgrade/adoption/overwrite на стар или реален store. UI version label е v1.14. Следва независимо наблюдение на този пилот и review за целева ОС/HTTPS/security/privacy/restore. Реални данни и инсталации не са променяни. **HOLD / NO-GO остава.**
