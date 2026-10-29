# Patient Portal — Fast Track17

Потребителят потвърди Windows15+ClamAV16 функционалния PDF сценарий: legacy scan/preview, ново качване/публикуване, owner view/download и отказ за друг пациент. Това е ръчна проверка; точният обхват е в [WINDOWS_ACCEPTANCE_BG.md](PatientPortal-FastTrack-v17/WINDOWS_ACCEPTANCE_BG.md). **HOLD / NO-GO остава.**

Следва **криптиран архив и отделно пробно възстановяване**. [Изтегли обновения проект17](downloads/PatientPortal_FastTrack_v17_Codex.zip), извлечи целия ZIP в нова папка, спри собствения портал8000 с Ctrl+C и стартирай **BACKUP_WINDOWS.cmd**. Новата парола за архива се въвежда локално и скрито, поне16 знака. Ползват се съществуващите FastTrack15 venv/data; няма ново init/reset или преинсталиране на ClamAV.

**RESTORE_TEST_WINDOWS.cmd** възстановява последния собствен архив в нова уникална папка. **START_RESTORED_WINDOWS.cmd** отваря възстановеното копие наlocalhost8001. Оригиналната data папка се запазва. [Точни стъпки](PatientPortal-FastTrack-v17/WINDOWS_BACKUP_BG.md).

18/18 regression групи PASS;15 оригинални backup проверки и11 нови desktop/drill случая. Поправено е изричното затваряне на readonly SQLite handles при config validation, без промяна на schema/crypto формата. Native Windows backup/getpass/drill предстои да се потвърди; Linux тестовете не го удостоверяват. [Действителен отчет](PatientPortal-FastTrack-v17/TEST_REPORT_BG.md).

Пакетът е 345387 bytes с135 source/report файла. SHA256: `4286401050f2c0a2ad90533b15aed571fa267cd758879bdb727d07b88ff05947`. В repository/ZIP няма .ppbk, пароли, DB/PDF, ключове, venv, ClamAV EXE/DLL/CVD. Предишните source версии14/15/16 и техните архиви са запазени отделно. Няма Windows service/firewall/registry/ACL/PATH промени. Само синтетични данни; реална употреба изисква независима проверка.
