> Актуализация v10: нормалната интеграция за нов synthetic store е описана в `CANDIDATE_START_BG.md`. Следва историческият дизайн/тестов профил; той не е production разрешение.

# Fast Track 9 — общ лимит и ingress прототип

**HOLD / NO-GO. Само изрично включвани синтетични fixtures. Няма production activation.**

## Реализирана политика

`app/shared_pdf_admission.py` добавя pure ASGI обвивка **извън** FastAPI/Starlette middleware-ите. Тя се включва от `install_synthetic_admission` само за изрично маркирана временна синтетична SQLite/storage папка. `app/portal.py`, всички HTML/CSS/JS и v8 AV модулът са непроменени. Обичайното стартиране продължава v8 поведението без този общ лимит. Инсталирането не изпълнява DDL и не променя Report/пациентски записи.

Един shared pool ограничава до **2 операции общо за всички worker-и** в тестовата конфигурация:

- GET/HEAD `/reports/{id}/preview`, `/view`, `/download`;
- POST `/reports/{id}/publish`, `/scan`;
- POST `/patients/{id}/reports`.

Вторият shared pool разрешава най-много **1 upload**; той е част от общия лимит, не допълнителен slot. При липса на slot или повредено shared състояние има 503 / Retry-After: 2, без прочитане на тялото и без изпълнение на parser/handler. Няма изчакваща неограничена опашка. Dashboard/login/health не вземат PDF slot; техните собствени rate/CPU лимити остават отделна задача. Генериране на credentials PDF, logo и останалите маршрути не са включени в тази PDF политика.

ASGI admission е **преди authentication**, за да ограничи multipart parsing; след допускане всички съществуващи auth/ownership/CSRF/AV проверки се изпълняват непроменени. Няма доверие на Cookie header за предварително заобикаляне на лимита. При претоварване неавтентикиран клиент може да получи 503 вместо обичайния auth отговор; не се разкриват пациентски данни. Това не заменя IP/rate/connection limits на проверен reverse proxy.

## Живот на slot-а

Глобалният slot се държи до завършването на целия ASGI app/response send, включително multipart parsing, синхронен upload/scan/publish и прехвърляне на тялото. Съществуващият per-process semaphore остава допълнителен вътрешен контрол.

При cancellation външната задача **не освобождава** slot, докато вътрешната задача още работи. Тя се изчаква и cancellation се предава след приключването ѝ. Това предотвратява допускане на ново сканиране, докато стар sync scanner thread още е активен. Няма TTL, който да обявява активна задача за свободна. Ако вътрешна задача блокира безкрайно, slot остава зает до приключване/процесен restart — fail-closed, а не гаранция за availability. Реалният upload scanner има собствен 30 s deadline от v8; спиране на blocking файлови операции/DB/външни услуги изисква отделни operational timeout-и.

## Файлови заключвания

Фиксирани файлове с по един байт: `flock(LOCK_EX|LOCK_NB)` на POSIX, `msvcrt.locking(LK_NBLCK)` на Windows. Отвореният descriptor притежава slot; close или процесен exit го освобождава. Няма TTL/lease expiry, обща SQLite write транзакция или Redis зависимост.

Shared state се подготвя **веднъж преди worker-ите**. Те валидират еднакви версия/capacity. Request path не създава или възстановява файлове. Невалиден slot, symlink, липсващ файл, несъответстваща capacity/версия или lock I/O грешка водят до отказ. Не изтривай/подменяй/мести state или lock файлове при живи worker-и: различни inode-и биха могли да създадат различни pools. Промяна на лимита изисква приключване на всички fixture worker-и и ново състояние.

Поддържаният модел е **една машина и доверена локална файлова система**. Няма доказателство за NFS/SMB/много host-ове, контейнери с различни mounts, hostile admin или правилни Windows ACL. POSIX modes не доказват Windows ACL. Текущата реална проверка е Linux; Windows реализацията не е изпитана тук.

## Ingress граници

- Upload body: до **15 MiB + 256 KiB** за multipart envelope; самият PDF продължава да има отделен лимит **15 MiB** в backend-а.
- Publish/scan POST форми: до **64 KiB** за цялото тяло.
- Content-Length над границата, двусмислен/невалиден header: отказ преди body read. Независимо от header-а реалните ASGI body байтове се броят; chunked/understated дължина не заобикаля лимита.
- Idle body read: **5 s**; абсолютен receive deadline: **30 s**. След EOF на тялото тези ingress timeout-и вече не се прилагат върху scanner/response/disconnect наблюдение.
- 413 за размер, 408 за receive timeout, 400 за прекъснат непълен upload. Multipart изключенията затварят частичните spooled файлове; downstream generic parser грешката се заменя с един точен отговор.

Това е ASGI граница; не ограничава вече приет transport chunk в Uvicorn, kernel/proxy буфери, headers, отворени connections или целия RAM на машината. Real reverse proxy/TLS/body/rate limits не са конфигурирани от този проект.

## Проверки

Група 14: 8 независими spawned процеса, точно 2 допуснати, recovery след нормално и аварийно приключване, отказ при shared state failure.

Група 15: refusal before read, общ лимит за всички посочени маршрути, upload sublimit, размер и timeout, repeated cancellation при още активна вътрешна работа, реален FastAPI multipart parser и затваряне на частичните временни файлове.

Група 16: собствени 2 временни HTTP worker-а, големи PDF граници, бавен mocked scan, outage/hold/recovery, HTTP disconnect, 30 s bounded soak и sampled CPU/RSS budgets. Подробно в `RESOURCE_POLICY_BG.md` и отчета. Няма автоматично production одобрение.
