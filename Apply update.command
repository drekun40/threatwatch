#!/bin/bash
# Applies the latest ThreatWatch update and restarts the dashboard. Output also saved to data/update.log.
cd "$(dirname "$0")" || exit 1
exec > >(tee data/update.log) 2>&1
export PYTHONUNBUFFERED=1
echo "== $(date)  Running offline tests"
.venv/bin/python -m pip install -q pytest >/dev/null 2>&1; .venv/bin/python -m pytest -q tests 2>&1 | tail -3
echo; echo "== Re-scoring unreviewed items with the Act now level"
.venv/bin/python run.py rescore --days 7
echo; echo "== Scan now (alerts + summary email)"
.venv/bin/python run.py scan
echo; echo "== Restarting the dashboard"
pkill -f "streamlit run app.py" 2>/dev/null; sleep 2
open "$(pwd)/Open ThreatWatch.command"
echo "== UPDATE DONE $(date)"
