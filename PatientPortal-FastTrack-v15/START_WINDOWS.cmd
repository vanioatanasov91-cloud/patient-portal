@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYLAUNCHER_ALLOW_INSTALL="
cd /d "%~dp0"
if not exist "%~dp0tools\desktop_start.py" goto extracted
where py >nul 2>&1
if errorlevel 1 goto python_missing
py -0p 2>nul | findstr /R /C:"^[ ]*-V:3[.]13[ *-]" /C:"^[ ]*-3[.]13[ *-]" >nul
if not errorlevel 1 goto python313
py -0p 2>nul | findstr /R /C:"^[ ]*-V:3[.]12[ *-]" /C:"^[ ]*-3[.]12[ *-]" >nul
if not errorlevel 1 goto python312
goto python_missing
:python313
py -3.13 -B "%~dp0tools\desktop_start.py"
goto finished
:python312
py -3.12 -B "%~dp0tools\desktop_start.py"
goto finished
:extracted
echo Разархивирайте целия ZIP и стартирайте START_WINDOWS.cmd от папката на проекта.
goto failed
:python_missing
echo Не е намерен Python 3.13 или 3.12 с py launcher. Вижте WINDOWS_START_BG.md.
echo Проверка на наличните версии: py -0p
goto failed
:finished
if errorlevel 1 goto failed
exit /b 0
:failed
echo.
echo Порталът не е стартиран. HOLD / NO-GO. Вижте WINDOWS_START_BG.md.
pause
exit /b 1
