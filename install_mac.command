#!/bin/bash
# ThreatWatch installer for macOS.
#  - copies the app to ~/ThreatWatch (outside Documents, so scheduled scans are allowed to run)
#  - creates a Python environment and installs packages
#  - schedules scans at 07:00 and 15:00 and the weekly report on Mondays 07:30
#  - opens the dashboard
# Safe to run again: your .env, keywords, sites and data are kept.

set -u
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/ThreatWatch"
LA="$HOME/Library/LaunchAgents"

say() { printf "\n\033[1m%s\033[0m\n" "$1"; }
fail() { printf "\n\033[31m%s\033[0m\n" "$1"; read -r -p "Press Enter to close."; exit 1; }

# ---- 1. find Python 3.10+
say "1/5  Finding Python"
PY=""
for c in python3.13 python3.12 python3.11 python3.10 /opt/homebrew/bin/python3 /usr/local/bin/python3 \
         /Library/Frameworks/Python.framework/Versions/Current/bin/python3 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    PY="$(command -v "$c")"; break
  fi
done
[ -n "$PY" ] || fail "Python 3.10 or newer is needed. Install it from https://www.python.org/downloads/macos/ and double-click this installer again."
echo "Using $PY ($("$PY" --version))"

# ---- 2. copy app (keep user files on re-install)
say "2/5  Installing to $DEST"
mkdir -p "$DEST"
tar -C "$SRC" --exclude './.venv' --exclude './data' --exclude './exports' --exclude './reports' \
    --exclude './.env' --exclude './config' -cf - . | tar -C "$DEST" -xf - || fail "Copy failed."
mkdir -p "$DEST/config" "$DEST/data" "$DEST/exports" "$DEST/reports"
for f in facilities.yaml keywords.yaml sources.yaml; do
  [ -f "$DEST/config/$f" ] || cp "$SRC/config/$f" "$DEST/config/$f"
done
[ -f "$DEST/.env" ] || cp "$SRC/.env.example" "$DEST/.env"
chmod +x "$DEST"/*.command 2>/dev/null

# ---- 3. python environment
say "3/5  Setting up Python packages (first time takes a few minutes)"
cd "$DEST" || fail "Cannot open $DEST"
[ -d .venv ] || "$PY" -m venv .venv || fail "Could not create the Python environment."
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt || fail "Package install failed. Check your internet connection and run the installer again."

# ---- 4. schedule
say "4/5  Scheduling scans (07:00 and 15:00, hourly around events and alerts) and the weekly report (Mon 07:30)"
mkdir -p "$LA"
write_agent() {  # label, args, calendar-xml
  cat > "$LA/$1.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$1</string>
  <key>ProgramArguments</key><array>
    <string>$DEST/.venv/bin/python</string><string>$DEST/run.py</string>$2
  </array>
  <key>WorkingDirectory</key><string>$DEST</string>
  <key>StartCalendarInterval</key>$3
  <key>StandardOutPath</key><string>$DEST/data/schedule.log</string>
  <key>StandardErrorPath</key><string>$DEST/data/schedule.log</string>
</dict></plist>
PLIST
  launchctl bootout "gui/$(id -u)/$1" 2>/dev/null
  launchctl bootstrap "gui/$(id -u)" "$LA/$1.plist" || echo "  (could not load $1 — it will load at next login)"
}
write_agent com.threatwatch.scan "<string>scan</string><string>--auto</string>" \
  "<dict><key>Minute</key><integer>0</integer></dict>"
write_agent com.threatwatch.report "<string>report</string>" \
  "<dict><key>Weekday</key><integer>1</integer><key>Hour</key><integer>7</integer><key>Minute</key><integer>30</integer></dict>"
echo "Scheduled. Log: $DEST/data/schedule.log"

# ---- 5. check + launch
say "5/5  Checking sources"
.venv/bin/python run.py demo >/dev/null 2>&1
.venv/bin/python run.py selftest
say "Done. Opening the dashboard — keep this window open while you use it."
echo "Add your API keys in: $DEST/.env   (then run 'Open ThreatWatch.command' in $DEST)"
open "$DEST"
exec .venv/bin/streamlit run app.py --browser.gatherUsageStats false
