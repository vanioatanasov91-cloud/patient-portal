# Patient Portal v1.18 — Fast Track18

**Само синтетични данни. HOLD / NO-GO.**

Потребителят потвърди Windows PDF сценария и backup/restore с версия 17. Избран е бъдещ пациентски достъп **през интернет от вкъщи**; домейн и сървър още няма. Работното име е **„Анакиевски“**. Предложение: `anakievski.bg` → `portal.anakievski.bg`, след потвърждение на регистрационна наличност/права и избор на доставчик.

Версия 18 доставя **план за внедряване**, изисквания за домейн/сървър и задание за независим преглед:

- **DOMAIN_AND_HOSTING_BG.md** — адрес, регистрационна проверка и изисквания към оферта.
- **INTERNET_DEPLOYMENT_BG.md** — архитектура,5 конкретни етапа и source-потвърдени технически граници.
- **INDEPENDENT_REVIEW_BG.md** — обхват и доказателства за независимото решение.
- **WINDOWS_ACCEPTANCE_BG.md** — точно разграничение между screenshots, потребителско потвърждение и непроверени сценарии.

Публичната DNS проверка не намери NS делегация за предложените имена, но регистрационната свобода остава непотвърдена. Няма поръчка/покупка, публичен server, DNS/firewall/service промени или реални пациентски данни.

В сегашния source candidate bootstrap е умишлено ограничен до localhost/synthetic данни. Legacy production входът не включва сам всички candidate AV/admission/freshness защити. Планът изисква отделен прегледан production bootstrap и versioned schema процедура, преди реална употреба. Това не се заобикаля с промяна на env/gate или публикуване на тестовия Windows server.

Функциите, българският интерфейс, кандидатската schema/config2, FastTrack15 desktop root/schema1, scanner16 и backup17 са запазени. Новият source има етикетv1.18. **За плана няма нужда да спираш/преинсталираш работещия портал.** Старите source версии и архиви остават отделни.

Всички 18 regression групи се пазят: `python -B tools/fasttrack_runner.py --include-synthetic`. Не са добавяни нови тестови групи за документните промени. Действителният отчет е TEST_REPORT_BG.md. Няма production readiness сертификат или независим approval.

Source/ZIP не съдържат passwords, DB/PDF, keys,.ppbk, venv или ClamAV binaries/databases. Точните source SHA manifests са обновени. **HOLD / NO-GO остава.**
