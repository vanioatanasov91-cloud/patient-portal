# Fast Track 14 — текущ pilot scanner

Текущият normal foreground Linux пилот, startup CVD/freshness preflight,25 real acceptance checks, restart и backup/restore са в PILOT_REPORT_BG.md. V14 пази собствен read-only verified snapshot за следващи serve пускания; няма автоматичен update timer/OS service. HOLD / NO-GO остава. Историческият V13 lab по-долу е отделен и не е текущият runtime.

---

# Fast Track 13 — актуален успешен FreshClam lab

**PASS/HOLD за този отделен synthetic lab; production HOLD / NO-GO остава.**

Действително обновена daily28168 от 29 октомври 2026, 08:24:16 ч. (Europe/Sofia); main/daily/bytecode digital signatures verified, live 48 h freshness true, protocol_passed true, 28 функционални проверки passed, exit0 и cleanup complete. Snapshot е read-only за clamd; няма candidate DB/PDF mounts. Всички собствени временни ресурси са премахнати; няма постоянна scanner/update услуга.

Подробности, exact hashes/timestamps/команда и граници: CLAMAV_UPDATE_BG.md, TEST_REPORT_BG.md, reports/last_signature_update.json и reports/last_real_clamav_check.json. Старите v12 freshness failures/CONNECT403 са исторически; не са текущият резултат. Следва историческият отчет за проследимост.

---

# Fast Track 12 — актуален real-ClamAV резултат

**HOLD / NO-GO. Няма успешно signature update.**

На 29 октомври 2026 г. е изпълнен промененият real lab с текущия official pinned image. **28/28 функционални проверки минаха**, включително offline main/daily/bytecode CVD signature verification чрез собствени verifier containers, loopback/non-root scanner, EICAR embedded в PDF, clean/publish/download, отказ при спрян daemon, recovery/legacy rescan и encrypted backup/restore. Изпълнение UTC: 04:14:03.573140 → 04:14:31.855970. Собствените ресурси са премахнати (cleanup_completed true).

Това изпълнение използва **необновените image бази**: daily 28164 / 25 Oct 2026 06:24 UTC. Freshness отново е false (>48 h), protocol_passed false, exit 1 и статус FUNCTIONAL_PASS/FRESHNESS_HOLD. То проверява функционалната съвместимост на променения lab; не доказва, че новият download път е преминал.

Отделният `--update-signatures` опит спря още при HTTPS proxy CONNECT403: UPDATE_BLOCKED/HOLD, exit 1, preflight_executed false, functional_passed 0. Кандидат/scanner от този update опит не са стартирани. Sanitized отчетите са съответно `reports/last_real_clamav_check.json` и `reports/last_signature_update.json`. Процедурата е в CLAMAV_UPDATE_BG.md. Сигнатурите не са обновени; не се използва fallback към старите бази в update пътя.

Следва историческият v11 отчет за контекст. V12 запазва image digest, ограниченията и HOLD.

---

# Fast Track 11 — истински ClamAV в отделен Linux тест

**HOLD / NO-GO. Функционалните проверки са успешни; signature freshness НЕ е успешен.**

Изпитан е официалният immutable образ:

```text
clamav/clamav@sha256:bda39705e291105049c3936e2803ac90b955172af8030f94f05dce1252df6c6d
ClamAV 1.5.4 / daily 28164 / 25 Oct 2026 06:24 UTC
```

Docker registry digest/checksum и TLS проверките са запазени. `sigtool --info` потвърди **Verification OK** за main, daily и bytecode CVD. Не са подменяни очаквани hashes/подписи, CA или часовник.

## Реално изпълнено

`tools/real_clamav_candidate_check.py --confirm-isolated-real-scanner-test` създаде собствен container/network и нормален двуработников кандидат само с генерирани акаунти/PDF/SQLite. Няма arbitrary target URL. Контейнерът работи като UID/GID 1000, с read-only root, dropped capabilities, no-new-privileges, 2 GiB RAM/2 CPU/pids 64, tmpfs за временни scanner файлове и без persistent Docker logs. Scanner-ът има само read-only clamd config mount — няма достъп до кандидат-базата или директорията с документи. Сканира INSTREAM байтовете.

Daemon-ът е в отделен Docker bridge, с host публикуване **само на 127.0.0.1**; в контейнера listener е 0.0.0.0:3310. Не е използван host networking. Bridge не е гаранция за пълен egress sandbox; clamd е стартиран директно, без updater, и работи с подписаните image бази. CVD верификационните контейнери са без мрежа.

**28/28 функционални проверки** минаха:

- Истински PING/PONG, clean INSTREAM и безвреден EICAR INSTREAM.
- Валиден генериран PDF с embedded EICAR е разпознат; действителният upload AV gate го отказа с 422, без Report/orphan PDF и без signature в потребителската грешка.
- Чист PDF премина реалния scanner → чернова → preview → publish → byte-for-byte owner download.
- Спиране на **собствения** scanner контейнер отказва ново качване с 503 и cleanup; стар attested/published PDF не е тихо оттеглен.
- След restart на scanner-а explicit legacy rescan и owner download работят.
- Проверен е малък scanner log sample: INSTREAM записите не съдържат генерираните patient usernames/original filename. Това не е пълен privacy audit или retention approval.
- След приключване на собствения кандидат е направен пълен AES-GCM backup/restore; възстановеният нормален кандидат запазва сесията, реално сканирания документ/AV evidence и SQLite integrity.

Собствените test server-и, контейнери и мрежи са приключени/премахнати. Няма scanner system install, Windows service/firewall/ACL/BitLocker или реална пациентска DB промяна. Образът остава само като cache за повторение, не е в ZIP.

## Неуспешно: актуалност на сигнатурите

Daily базата от 25 октомври е над зададения **48 h** праг към проверката на 28 октомври. Затова `signature_age=false`, `protocol_passed=false`, script exit **1** и статус **FUNCTIONAL_PASS/FRESHNESS_HOLD**. Това не е зелена operational готовност. Main/bytecode могат законно да са по-стари; проверката за freshness използва daily timestamp, а не възрастта на целия образ.

Заявката към официалния `https://database.clamav.net/daily.cvd` получи **HTTP 403 от мрежовата политика**. Домейнът `database.clamav.net` е записан в конфигурационната чернова, без промяна на preset домейните. Черновата е потвърдена като saved; това **не я прилага или публикува**.

За актуализация трябва в настройките на облачната среда да се прегледа/запише това мрежово допълнение и средата да се публикува. След реално прилагане е нужна повторна connectivity проверка, FreshClam update с включена TLS/CVD проверка и нов preflight. Не се заобикаля proxy/allowlist, не се понижава freshness прагът и не се използват неофициални mirrors. Тази част не е завършена.

## Повторение на функционалния lab

Следвай runtime Docker/proxy/CA указанията на облачната среда. Изтегли отделно проверения official digest; script-ът не pull-ва или инсталира като скрит страничен ефект. След това:

```bash
python -B tools/real_clamav_candidate_check.py --confirm-isolated-real-scanner-test
```

Точно този pinned образ остава със същите стари бази при повторение и очаквано не покрива 48 h freshness. За актуални бази е нужна отделна проверена update процедура/нов official digest и повторно реално изпитване; текущият отчет не обещава бъдещ PASS.

Windows/HTTPS, OS ACL/BitLocker, същински malware coverage, дълъг load, независим restore/privacy/security/deployment sign-off остават отделни изисквания. **HOLD / NO-GO остава независимо от EICAR успеха.**
