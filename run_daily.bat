@echo off
REM Runs the domain check once. Used by Windows Task Scheduler (see setup_schedule.ps1).
cd /d "%~dp0"
if not exist results mkdir results
where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)
echo ===== %date% %time% =====>> results\log.txt
%PY% check.py >> results\log.txt 2>&1
