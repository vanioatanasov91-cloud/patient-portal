# Patient Portal — Fast Track 15

За локално Windows стартиране изтегли **downloads/PatientPortal_FastTrack_v15_Codex.zip**, извлечи целия пакет и стартирай **START_WINDOWS.cmd**. Той използва installed Python3.13 (резервен3.12), source-relative paths и own LOCALAPPDATA test store. Native Windows startup трябва да се потвърди на целевия компютър; tests са в Linux плюс Windows wheel dry-run. Подробности: PatientPortal-FastTrack-v15/WINDOWS_START_BG.md.

Пакетът съдържа 118 source/report файла, 304038 bytes. SHA256: `272051aafdc3be55fe4c10a451ba204326a11e4df69d50c5ce70f7a60ab63295`. Няма passwords/DB/PDF/keys/runtime stores/ClamAV databases.

18/18 regression groups PASS,31 fixed Windows64/CPython3.13 wheels resolved;9 desktop cases допълват непроменените предишни tests. Code е и в PatientPortal-FastTrack-v15/. Предишната версия14 и нейният ZIP са запазени отделно. Runtime data и venv остават извън source/repository.

Login/UI/branding са достъпни без scanner; PDF upload/rescan изискват отделно подготвен local UTC clamd/48h precheck. Няма automatic Python/ClamAV/service/firewall/ACL install. **HOLD / NO-GO остава до независим review. Само synthetic данни, няма production approval.**
