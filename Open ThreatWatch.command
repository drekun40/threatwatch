#!/bin/bash
# Opens the ThreatWatch dashboard. Keep this window open while you use it; close it to stop.
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/streamlit ]; then
  echo "ThreatWatch isn't installed here yet. Double-click install_mac.command first."
  read -r -p "Press Enter to close."; exit 1
fi
exec .venv/bin/streamlit run app.py --browser.gatherUsageStats false
