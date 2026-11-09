#!/bin/bash
# ThreatWatch launcher for macOS / Linux. Double-click (macOS) or run: ./start_mac.command
cd "$(dirname "$0")" || exit 1

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.10 or newer is required. Install it from https://www.python.org/downloads/ and run this again."
  read -r -p "Press Enter to close."
  exit 1
fi

if [ ! -d .venv ]; then
  echo "First run: setting up (takes a minute or two)…"
  python3 -m venv .venv || { echo "Could not create the virtual environment."; read -r -p "Press Enter to close."; exit 1; }
fi
source .venv/bin/activate
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt || { echo "Package install failed — check your internet connection."; read -r -p "Press Enter to close."; exit 1; }

[ -f .env ] || cp .env.example .env

echo ""
echo "Checking sources…"
python run.py selftest
echo ""
echo "Opening the dashboard in your browser. Leave this window open; close it to stop ThreatWatch."
streamlit run app.py
