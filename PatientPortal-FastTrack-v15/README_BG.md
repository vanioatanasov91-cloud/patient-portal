# Patient Portal v1.15 — Fast Track 15

**HOLD / NO-GO. Само локален synthetic портал; няма production approval.**

За Windows10/11 извлечи целия ZIP и стартирай **START_WINDOWS.cmd**. Той избира наличния Python3.13 (резервен3.12), използва папката на проекта автоматично, проверява грешките и отваря браузъра след успешен старт. Не е нужно ръчно сменяне от system32 или избор на default3.15.

Подробните стъпки, постоянният път за тестовите акаунти и настройките на центъра са в **WINDOWS_START_BG.md**. Read-only диагностика: **CHECK_WINDOWS.cmd**. Данни/venv са в собствен versioned LOCALAPPDATA root извън source; старите папки не се мигрират/презаписват. Повторното стартиране пази sessions/reports/AV evidence. Launcher-ът не инсталира Python/ClamAV/Docker и не променя услуги/firewall/ACL/ExecutionPolicy.

Desktop режимът добавя explicit --require-fresh-scanner към normal candidate serve. Login/UI/branding работят без scanner; PDF upload/rescan изискват localhost ClamAV, UTC VERSION и сигнатури до48h. За scanner на Windows следва отделна operator процедура. Linux pilot от v14 е запазен отделно в PILOT_BG.md; Windows launcher не го активира.

Всичките **18 regression групи** остават. Group17 изпълнява старите42 candidate assertions,8 pilot cases и9 bootstrap cases. Windows64/CPython3.13 зависимостите са проверени с pip dry-run; native CMD/GUI/ACL/Windows multiprocessing не са изпълнявани тук. Actual резултати: TEST_REPORT_BG.md.

```bash
python -B tools/fasttrack_runner.py --include-synthetic
```

Българският интерфейс/URL/workflow, candidate schema2, AV/shared admission и encrypted backup са запазени. Desktop marker/schema1 е отделен; няма автоматично включване на real data или production migration. UI label е v1.15. **HOLD / NO-GO остава до независим review.**
