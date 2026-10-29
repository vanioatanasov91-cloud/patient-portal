# Patient Portal v1.16 — Fast Track 16

**HOLD / NO-GO. Само synthetic портал.**

Потребителят потвърди local Windows15 login/settings; Docker Desktop липсва. V16 добавя **portable ClamAV companion**, който работи до вече пуснатия портал и не променя неговите accounts/data/settings. Най-малкият download за тази стъпка е PatientPortal_ClamAV_Windows_v16.zip → Extract All → **START_CLAMAV_WINDOWS.cmd**. Инструкции: **CLAMAV_WINDOWS_BG.md**.

При първо пускане се изтегля official pinned Windows64ClamAV1.5.4 (около226MB) и CVD базите. Package size/hash, safe runtime extraction, native sigtool signatures,48h и PING/clean/EICAR preflight се проверяват преди ready. Scanner-ът е само127.0.0.1:3310, foreground като обикновен user. Няма Docker/Windows service/registry/firewall/ACL/global PATH/portal migration. Остави scanner прозореца отворен и пробвай генериран PDF в текущия портал.

Пълният проект запазва START_WINDOWS.cmd/CHECK_WINDOWS.cmd за портала. При изрично използване на source16 се пази съвместимият собствен desktop root FastTrack15/schema1 и candidate/schema2; няма reset/adoption на real store. Старите source releases са отделни. Българските workflow-и/AV/shared/backup са запазени; UI label v1.16. За scanner добавката не е нужно да сменяш вече работещия source15.

Regression suite остава **18 groups**. Group12 изпълнява старите scanner tests и12 portable package/config/update guard cases. Windows vendor ZIP реално е изтеглен/проверен/извлечен и PE x64 headers са проверени в Linux; native Windows EXE не са изпълнявани тук. Actual Windows scanner/preflight/upload остава да се потвърди при потребителя. TEST_REPORT_BG.md описва точните evidence/граници; няма независим approval.

```bash
python -B tools/fasttrack_runner.py --include-synthetic
```

Package/CVD/runtime files и пароли/DB/PDF не влизат в source ZIP или GitHub. Само синтетични тестови данни. **HOLD / NO-GO остава.**
