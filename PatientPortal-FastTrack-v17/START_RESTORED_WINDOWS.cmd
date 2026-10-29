@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
cd /d "%~dp0"
if not exist "%~dp0tools\windows_backup.py" goto extracted
set "PP_BACKUP_PY=%LOCALAPPDATA%\PatientPortal\FastTrack15\venv\Scripts\python.exe"
if not exist "%PP_BACKUP_PY%" goto missing
"%PP_BACKUP_PY%" -B "%~dp0tools\windows_backup.py" serve-restored --confirm-synthetic-desktop-backup
if errorlevel 1 goto failed
pause
exit /b 0
:extracted
echo Извлечете целия ZIP и стартирайте START_RESTORED_WINDOWS.cmd от папката на проекта.
goto failed
:missing
echo Не е намерена средата на тестовия портал. Вижте WINDOWS_BACKUP_BG.md.
goto failed
:failed
echo.
echo Операцията не е завършена. HOLD / NO-GO. Вижте WINDOWS_BACKUP_BG.md.
pause
exit /b 1
