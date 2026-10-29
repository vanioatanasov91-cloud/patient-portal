# Patient Portal — Fast Track 16

За вече работещия Windows портал15 без Docker изтегли **[ClamAV добавката](downloads/PatientPortal_ClamAV_Windows_v16.zip)**, извлечи целия ZIP в нова папка и стартирай **START_CLAMAV_WINDOWS.cmd**. Остави портала да работи. Добавката не чете/променя неговите данни, потребители и настройки. Инструкции: [CLAMAV_WINDOWS_BG.md](PatientPortal-FastTrack-v16/CLAMAV_WINDOWS_BG.md).

Малкият пакет е 16304 bytes с6 text/source файла. SHA256: `a13529acbcaf0f80eeb7a605055486ea68b79cc3fe53a269ee49202cb6d303dd`. При първото пускане изтегля и проверява официалния ClamAV1.5.4 Windows64 пакет (около226MB) и подписаните бази. Готовността се показва след реален PING/clean/EICAR/48h preflight на целевия компютър. Няма Docker/Windows service/firewall/registry/ACL/global PATH промени. Само127.0.0.1:3310 и собствена LOCALAPPDATA папка.

Пълният обновен проект е **[Fast Track16](downloads/PatientPortal_FastTrack_v16_Codex.zip)**: 326006 bytes,126 source/report файла, SHA256 `2b4e0b101aa3a4282f5adaaa0a0e549ca5457412419b8ba8f48728afc1b79628`. Не е нужно да сменяш работещия портал15 за тази scanner стъпка. Старите версии14/15 и техните ZIP са запазени отделно.

**18/18 regression групи PASS**; новите12 случая допълват запазените предишни тестове. Официалният Windows ZIP е реално проверен/извлечен в Linux. Native Windows ClamAV execution и целевото PDF качване остават да се потвърдят. [Действителен отчет](PatientPortal-FastTrack-v16/TEST_REPORT_BG.md).

В доставените source/ZIP няма vendor EXE/DLL/CVD, пароли, PDF, ключове или база на портала. **Само синтетични данни. HOLD / NO-GO остава до независима проверка.**
