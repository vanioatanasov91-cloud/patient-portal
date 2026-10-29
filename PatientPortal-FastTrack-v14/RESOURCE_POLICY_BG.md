> Актуализация v10: нормалната интеграция за нов synthetic store е описана в `CANDIDATE_START_BG.md`. Следва историческият дизайн/тестов профил; той не е production разрешение.

# Fast Track 9 — големи PDF и ограничен продължителен товар

**HOLD / NO-GO. Само генерирани временни данни и собствен loopback server.**

```bash
python -B tools/synthetic_resource_load.py
```

Няма target URL аргумент. По подразбиране bounded soak е **30 секунди**; за диагностика се допуска `--soak-seconds 10` до 60. Това е продължение на еднократната v8 проба, не многочасова capacity сертификация.

Harness-ът подготвя собствена временна SQLite, генерирани ReportLab PDF с коментарно допълване до точния размер, случайни synthetic сесии и общи lock pools. Стартира 2 Uvicorn worker-а само на `127.0.0.1` и случаен резервиран порт. Няма реален clamd — в собственото worker bootstrap кодът му се заменя с явно фалшив scanner. Не се променят системни услуги/firewall/ACL/BitLocker или реални DB/PDF. Накрая само създаденият server и worker-и се приключват/изчакват, временните данни се премахват.

## Какво проверява

- Два worker-а използват **общи 2 PDF slots и 1 upload slot**; parent test може да заеме същия pool и да получи предвидим 503 от HTTP download/publish/scan/upload преди parser.
- Upload **15 MiB** е приет като непубликувана чернова с точен SHA256; **15 MiB + 1 byte** е отказан с 413, без нов Report. Прекалено голямото цяло body също е отказано.
- Legacy download **64 MiB** е byte/hash проверен със streaming клиент; **64 MiB + 1 byte** е отказан с 409. Друг пациент получава 404.
- 8 едновременни 64 MiB изтегляния имат успешни точни отговори и 503/Retry-After. Стойностите са измерени, не се предполага, че всички заявки трябва да успеят.
- При HTTP stream close/disconnect, бавни mocked scan операции и scanner outage има recovery на shared slots и запазен AV hold до изричен clean rescan.
- 8 HTTP клиента извършват повтарящи се изтегляния за 30 s. Всеки 200 е byte-for-byte проверен. 503 се отчита отделно като отказ за повторение, не като доставен PDF. Latency се отчита **отделно за 200 и 503**.
- Същите два PID остават живи след фазите; проверката ползва нови TCP връзки, защото keep-alive връзката остава при един worker.

Оригиналният `tools/synthetic_http_load.py` и неговата 32-request/24-patient група 13 са запазени без промяна. Той все още тества v8 без включен shared admission; новата група 16 проверява v9 слоя. Всичките предишни 13 групи остават, общо **16**.

## Ресурсен профил и бюджети

Няма costly builds. Тестовете използват готовия изолиран Python venv, 2 worker-а, максимум 8 активни HTTP клиента и ограничени временни файлове. PDF са генерирани само в TEMP, не в архива.

На Linux се семплират `/proc` RSS и CPU на двата worker-а. Профилът се счита за неуспешен при sampled aggregate RSS над **1 GiB** или сумарно worker CPU време над **2×soak_seconds + 20 s** за цялата проба. Това са **тестови regression budgets**, не приложени cgroup/Windows Job/OS лимити. RSS семплите може да пропуснат кратък peak; не включват client/parent, реален scanner, proxy или kernel буфери. На неподдържана платформа стойностите са null, бюджетите са неизмерени; не се представят за потвърдени.

Само G=2 активни protected operations могат да държат големи PDF snapshots едновременно в този fixture. При L=64 MiB основните payload-и са до G×L=128 MiB. Допълнителни read/copy/ASGI/scanner/temp буфери, Python allocator, DB и останалите endpoints добавят памет. За предварителен модел отдели поне още толкова за копия, плюс idle workers/ОС/scanner. **Това не е общ доказан RAM bound.** Login/Argon2 и останалите маршрути са извън PDF slots.

Изходът е `reports/last_synthetic_resource_load.json`: граници, статуси, latency по статус, measured duration, sampled RSS, CPU, budgets и ограничения. Числата не са production SLO. Не се записват cookies, пароли, PDF съдържание или пациентски метаданни.

## Оставащо

Истински reverse proxy/transport header/body/rate limits, OS enforced CPU/RAM/disk limits, многочасов soak, повече workers, реален scanner и неговите буфери, filesystem/Windows locking/ACL, много host-ове и независими deployment/security/privacy/restore доказателства остават отделни задачи. Подробностите на общия лимит и cancellation са в `SHARED_ADMISSION_BG.md`. HOLD / NO-GO не се променя.
