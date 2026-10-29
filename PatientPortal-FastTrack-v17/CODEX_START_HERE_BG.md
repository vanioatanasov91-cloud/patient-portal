# Продължение след Fast Track17

Първо AGENTS.md, README_BG.md, WINDOWS_ACCEPTANCE_BG.md, WINDOWS_BACKUP_BG.md, TEST_REPORT_BG.md и NEXT_SPRINT_BG.md.

Потребителят реално потвърди Windows15+ClamAV16 ready screenshot, legacy scan/preview, upload/publish, owner view/download, other user direct-link refusal. Записът различава screenshot и user report; няма independent approval или Windows HTTP trace. Не го връщай към повторно инсталиране на Python/Docker/ClamAV или пак към завършените PDF стъпки без конкретна грешка.

V17 добавя BACKUP_WINDOWS.cmd / RESTORE_TEST_WINDOWS.cmd / START_RESTORED_WINDOWS.cmd и tools/windows_backup.py. Съществуващата собствена среда/данни FastTrack15 се пазят. Архивът се създава offline, с hidden getpass и existing AES-GCM API; restore само в нова уникална папка, drill server само localhost8001 с freshness hook. Не чети/печатай/публикувай архиви/keys/accounts/DB/PDF. Няма real install/migration/service/firewall промени.

candidate_runtime.read_config вече затваря изрично readonly SQLite handles на success/error. Schema/marker/desktop identity не се променят. Старите тестове са непроменени; група18 първо old15 backup assertions, после11 desktop cases. Default suite пази18 групи. Новите Win CMD/getpass/restore native действия остават целеви операторски тест, не се твърдят като изпълнени в Linux.

Доставяй новата версия чрез проверена public GitHub download връзка. Sandbox/workspace links не работят при потребителя. За production остава HOLD / NO-GO до независим review.

Корекцията затваря изрично и новосъздадената lifecycle SQLite връзка след commit, преди преименуване на възстановената директория. Проверен е и запазеният marker след затварянето.
