# Fast Track 15 — локална настройка на Windows

**HOLD / NO-GO. Само синтетични данни. Windows изпълнението изисква проверка на целевия компютър.**

## 1. Стартиране

Извлечи **целия ZIP** с „Извлечи всички“. В папката PatientPortal-FastTrack-v15 стартирай **START_WINDOWS.cmd** с двоен клик, като обикновен потребител. Launcher-ът сам използва папката си; текущият system32/Downloads prompt няма значение. При непълно разархивиране спира с обяснение.

Наличният Python3.13 от py launcher се предпочита; резервен е3.12. Default3.15 не се избира. Не се инсталира/премахва Python и не се променят PATH, ExecutionPolicy, Windows services, firewall или ACL. Няма Administrator режим.

При първо пускане се проверяват source hashes, създава се собствен venv и се инсталират фиксираните зависимости с готови binary wheels. Всеки native exit се проверява; при грешка следващите стъпки са спрени. Пакетите за Windows64/CPython3.13 са разрешени чрез pip dry-run в тази итерация; това не е реално Windows execution доказателство.

След успешен init/check/HTTP startup браузърът се отваря на **http://127.0.0.1:8000/login**. Остави прозореца отворен. Спиране: Ctrl+C. При следващо пускане натисни пак START_WINDOWS.cmd — без повторен init/reseed/overwrite.

## 2. Тестови акаунти и данни

Собственият desktop root е `%LOCALAPPDATA%\PatientPortal\FastTrack15`. Candidate/schema2 е в подпапка `data`, venv е отделен. Отвори локално с Notepad файла:

```text
%LOCALAPPDATA%\PatientPortal\FastTrack15\data\synthetic-accounts.json
```

В Explorer адресната лента приема този път. Използвай `username` и съответната `password` за synthetic_staff, synthetic_patient или synthetic_other. **Не изпращай файла или паролите в чат.** Launcher-ът печата само пътя; не пази паролите в source/ZIP/logs.

Данните и сесиите остават при stop/restart. Старите v14/други папки не се приемат/мигрират и не се променят. Непознат/неподготвен desktop root се отказва; не изтривай папката с данни, за да отстраниш package error. При непълен venv запази data и виж диагностиката.

## 3. Настройки на центъра

Влез като synthetic_staff и отвори **„Настройки на центъра“** или http://127.0.0.1:8000/settings. За текущата проверка използвай измислени данни, например „Демо медицински център“, demo@example.invalid и тестово лого PNG/JPG до2MB. Натисни „Запази настройките“. Името/логото се показват в портала; пациентите нямат служебен достъп до тези настройки. Не добавяй реални пациенти/PDF.

## 4. ClamAV за PDF

Login/UI/настройките могат да работят без scanner. Upload/rescan изискват **локален clamd на127.0.0.1:3310**, актуални сигнатури и independently confirmed UTC VERSION timestamp. Desktop launcher използва --require-fresh-scanner: всяко качване/rescan проверява VERSION/48h и после истински INSTREAM. Outage/stale/future/malformed →503; няма off/fake-clean fallback. Това не заменя digital signature/source/log/privacy review.

START_WINDOWS.cmd **не инсталира и не конфигурира** ClamAV или Docker Desktop. След работещ login следва отделна процедура за scanner на този Windows компютър. Ако Docker Desktop вече работи с Linux containers, операторът може да подготви отделен synthetic scanner container с official image и host publish само127.0.0.1:3310, TZ=UTC и проверен update/preflight. Не свързвай към реален scanner/service/DB и не променяй Windows services/firewall/ACL/BitLocker без отделна изрична процедура.

Изпълнените v13/v14 Linux ClamAV проверки са исторически, не доказателство за scanner на новия Windows компютър. Scanner readiness диагностиката използва само localhost VERSION; успешният резултат не удостоверява digital signatures/authenticity.

## 5. Диагностика

Стартирай **CHECK_WINDOWS.cmd**. Той не създава venv/DB/акаунти и не инсталира нищо. Показва Python/source integrity/venv/candidate/scanner flags без пароли/ключове. При грешка изпрати само текста на грешката или тези flags; не изпращай synthetic-accounts.json, candidate-secret, .env, DB/PDF.

При зает8000 затвори предишния **собствен** тестов портал. Launcher-ът не убива чужди процеси. При едновременно второ пускане desktop SQLite lock отказва дублиране. При package failure запази данните; повторното START_WINDOWS.cmd проверява зависимостите и продължава само след успешна инсталация.

Native CMD, Windows GUI/browser association, ACL и Windows multiprocessing не са изпълнени в Linux средата. Преносимата bootstrap логика/normal HTTP/freshness flag са тествани със synthetic fixtures; всички стари regression groups се запазват. Преди реални пациенти остава независим Windows/deployment/security/privacy/backup/scanner review. **HOLD / NO-GO остава.**
