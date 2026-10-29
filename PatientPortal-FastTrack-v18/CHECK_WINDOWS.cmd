@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYLAUNCHER_ALLOW_INSTALL="
cd /d "%~dp0"
if not exist "%~dp0tools\desktop_start.py" goto failed
py -0p 2>nul | findstr /R /C:"^[ ]*-V:3[.]13[ *-]" /C:"^[ ]*-3[.]13[ *-]" >nul
if not errorlevel 1 goto python313
py -0p 2>nul | findstr /R /C:"^[ ]*-V:3[.]12[ *-]" /C:"^[ ]*-3[.]12[ *-]" >nul
if not errorlevel 1 goto python312
echo Не е намерен Python 3.13 или 3.12. Изпълнете py -0p.
goto failed
:python313
py -3.13 -B "%~dp0tools\desktop_start.py" --diagnose
goto finished
:python312
py -3.12 -B "%~dp0tools\desktop_start.py" --diagnose
goto finished
:failed
echo Проверете дали целият ZIP е разархивиран. Вижте WINDOWS_START_BG.md.
:finished
pause
