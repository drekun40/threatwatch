@echo off
rem ThreatWatch launcher for Windows. Double-click this file.
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY goto nopython

if not exist .venv (
  echo First run: setting up ^(takes a minute or two^)...
  %PY% -m venv .venv || goto nopython
)
call .venv\Scripts\activate.bat
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt || goto installfail

if not exist .env copy .env.example .env >nul

echo.
echo Checking sources...
python run.py selftest
echo.
echo Opening the dashboard in your browser. Leave this window open; close it to stop ThreatWatch.
streamlit run app.py
goto :eof

:nopython
echo Python 3.10 or newer is required. Install it from https://www.python.org/downloads/
echo During install, tick "Add python.exe to PATH". Then double-click this file again.
pause
goto :eof

:installfail
echo Package install failed - check your internet connection and try again.
pause
