> V14: real scanner lifecycle/per-scan readiness и offline refresh за foreground Linux pilot са описани в PILOT_BG.md; actual evidence е в PILOT_REPORT_BG.md. Това не е Windows/system service deployment или independent approval.

> V13: истинското official FreshClam update, CVD digital signatures и 48 h preflight са passed в отделния временен lab. Текущи доказателства: CLAMAV_UPDATE_BG.md. По-долу са исторически указания; няма production approval.

> V12: изричният FreshClam snapshot/update път и действителният HTTP403 отказ са в CLAMAV_UPDATE_BG.md. Старите операторски процедури по-долу не са production approval.

> V11: реалният ClamAV lab е изпълнен; функционалните проверки са успешни, daily freshness е FAILED/HTTP403 blocked. Текущи резултати и граници: REAL_CLAMAV_REPORT_BG.md. Следва историческата операторска процедура.

# Fast Track 8 — ClamAV независим операторски preflight

**HOLD / NO-GO. В тази итерация реален scanner не е инсталиран или проверен.**

`tools/clamd_preflight.py` не импортира портала и не отваря DB/PDF. По подразбиране CLI не прави мрежова проба. Само оператор, в отделна одобрена процедура на тестова scanner инсталация, може да изпълни:

```bash
python -B tools/clamd_preflight.py --confirm-local-operator-check --signature-timezone UTC
```

Използвай UTC само ако независимо е потвърдено, че VERSION timestamp на daemon-а е в UTC; иначе посочи провереното IANA име. Timestamp няма timezone в протокола и инструментът не може да го познае. Прагът е 48 часа, конфигурируем 1–168 часа, не автоматично одобрена организационна политика.

Пробите са само към `127.0.0.1:3310` (или явно зададен локален порт): PING/PONG, VERSION parse и възраст на signature timestamp, синтетичен clean INSTREAM контрол, безвреден EICAR INSTREAM контрол. Няма файл EICAR на диск, външни заявки, инсталиране, firewall/ACL или daemon промени. Непълен отговор, липса на EICAR detection, бъдещи/стари сигнатури и outage са fail-closed. Изходът съдържа само сборни булеви резултати, без raw daemon reply или malware signature. Пробата е с 3 s socket timeout / 10 s deadline на команда.

В upload интеграцията е затегнато приемането на zINSTREAM отговор: изисква се пълен NUL терминатор; truncated OK вече се отказва. Има 30 s общ deadline за scan, освен краткия socket timeout; това не замества reverse proxy/ingress лимит.

Независимият оператор задължително проверява отделно:

1. Listener е обвързан само към loopback; портът не е достъпен през LAN/WAN. Успешният localhost PING не доказва това.
2. Версията е поддържана, подписите/източникът на updates са доверени и актуални; timezone е потвърдена. VERSION сам по себе си не доказва автентичност.
3. Scanner service identity, права, timeout/stream-size/queue limits покриват 15 MiB и натоварването; няма достъп до пациентската DB.
4. Log privacy/redaction, retention, monitoring/alerts и отказ при update/scanner failure са проверени независимо. EICAR може да задейства scanner лог/аларма.
5. Действителните upload rejection/cleanup и recovery работят в одобрена изолирана инсталация; текущите автоматични тестове са само mocked.

Зелен `protocol_passed` никога не променя HOLD / NO-GO и не одобрява legacy migration.
