# ClamAV за вече работещия Windows портал

**HOLD / NO-GO. Само синтетични PDF. Това е отделен foreground scanner за localhost.**

## Кое да изтеглиш

За работещата версия15 използвай малкия **PatientPortal_ClamAV_Windows_v16.zip**. Извлечи го в нова папка и остави прозореца/браузъра на портала както са. Добавката не чете/променя portal DB, accounts, settings или venv. Няма нужда да стартираш нов портал или да местиш въведеното име/лого.

Пълният Fast Track16 проект също включва същите scanner файлове. Неговият START_WINDOWS.cmd запазва съвместимия desktop root FastTrack15/schema1 и candidate/schema2, ако изрично се стартира новият source; няма migration/reset/reseed. За тази scanner стъпка не е нужно да сменяш работещия portal source.

## Пускане

1. В извлечената папка стартирай **START_CLAMAV_WINDOWS.cmd**, с обикновен потребител. Python3.13 се предпочита пред3.12, default3.15 не се избира.
2. При първо пускане ще бъдат изтеглени official ClamAV ZIP **225774978 bytes (около226MB)** и подписаните main/daily/bytecode бази (още приблизително110MB). Остави време за download/зареждане; обикновено няколко минути според интернет/компютъра. Нужни са поне около1GB свободен диск за кеш/обновявания. Runtime subset се разархивира без големите debug symbols.
3. Изчакай съобщението **„ClamAV е готов на 127.0.0.1:3310“**. То се показва само след реален PING/clean/EICAR/48h preflight на този компютър.
4. Остави scanner прозореца отворен. Върни се в вече работещия портал и пробвай малък **генериран тестов PDF**. В служебния акаунт: тестов пациент → качване → преглед → публикуване → вход като owner patient. За наследения synthetic пример ползвай „Провери с антивирус“.

Проверка по желание: **CHECK_CLAMAV_WINDOWS.cmd**. Той проверява само маркирания работещ scanner и показва sanitized flags; използва безвредния EICAR контрол в паметта. Не записва EICAR файл, не чете пациентски PDF/DB и не променя статуса HOLD.

Спиране: Ctrl+C в scanner прозореца. Спира се само създаденият от него процес; порталът и данните му се запазват. След спиране ново качване/rescan ще отказват, докато scanner-ът отново е готов. Вече атестирани документи не се оттеглят/изтриват тихо.

## Какво се настройва

Собствен root: `%LOCALAPPDATA%\PatientPortal\ClamAV-Portable1`. Не е Program Files или съществуваща ClamAV инсталация. Непозната папка/зает3310 се отказват; няма overwrite или спиране на чужди процеси. Windows service, Docker, registry, firewall, ACL, global PATH, ExecutionPolicy и OS clock не се променят. Не се изключва друг антивирус.

Източникът е official immutable release asset:

```text
https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip
SHA256: 0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395
```

Download е HTTPS с включена certificate проверка и ограничени official GitHub redirect hosts; size/hash се проверяват преди извличане/изпълнение. Това удостоверява package integrity спрямо публикувания vendor release, а не независимо Authenticode/production одобрение. В кода няма arbitrary URL, mirror или опция за изключване на TLS/AV. Vendor EXE/DLL/CVD не са включени в source/GitHub/малкия starter ZIP.

FreshClam се пуска явно от helper-а при първа подготовка и при следващо пускане след24h; минимум1h между опити. Няма скрит update service/timer. Новият snapshot е offline и се избира след sigtool digital signature verification на трите пълни CVD и48h свежест. Не се променя live mounted database. При update failure предишните бази се пазят за преглед, но текущото пускане не преминава в ready/fallback. Спри scanner-а и го пускай отново ежедневно за обновяване.

Native процесът е foreground с TCPAddr127.0.0.1/3310, explicit private database/cert/temp/log directories,2 threads/4 queue,15MB portal uploads с20MB stream bound, ограничен scan size/time/recursion и AlertExceedsMax. Няма patient-file path към scanner-а; порталът праща само INSTREAM байтовете. Child TZ=UTC0/LC_ALL=C, без промяна на системната Windows timezone. След startup периодичният контрол проверява VERSION/48h без повторни EICAR alarms; при загуба на готовност спира собствения scanner.

## При грешка

Не пускай като Administrator и не изключвай TLS/firewall/антивирус. Запази текста на HOLD/грешката, без .env/keys/accounts/DB/PDF. При зает3310 добавката не избира автоматично друг/чужд scanner. При update отказ изчакай поне1h преди нов опит. При непълен/повреден runtime запази portal data; scanner папката е отделна и има private диагностични файлове. Не изпращай native logs с реални данни.

Official Windows пакетът включва нужните runtime DLL; не е приложен MSI/system installer. Поддържан е Windows64 x64 с Python3.13/3.12. Actual native Windows download/FreshClam/clamd/CVD/preflight/portal upload трябва да се потвърдят на твоя компютър. Linux проверките на source/package/PE headers и mocked guards не са native Windows certification.

Официална процедура за конфигурация: https://docs.clamav.net/manual/Usage/Configuration.html#windows . Независим deployment/security/privacy/backup/scanner review остава преди реални пациенти. **HOLD / NO-GO остава.**
