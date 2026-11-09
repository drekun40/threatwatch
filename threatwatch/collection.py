"""Collection log in the analyst template's format.

Template columns (in this order):
  Date Collected | Analyst Initials | Collection Phase (General/Industry OR Facility-Specific) |
  Tool / Platform Used | Source Name | Source URL / Citation | Source Tier | Source Reliability |
  Raw Information | Analyst Notes | Preliminary Threat Level (Low, Moderate, High)

How ThreatWatch fills them:
  Date Collected        when ThreatWatch first collected the item (ET)
  Analyst Initials      your initials (Admin > Scans & alerts); automated rows can be re-initialled on review
  Collection Phase      Facility-Specific if the item names or sits inside a monitored site, else General/Industry
  Tool / Platform Used  ThreatWatch plus the platform it came through (Google News RSS, NWS API, ...)
  Source Name           outlet, account or agency
  Source URL / Citation link; when there is none, a citation (source, date)
  Source Tier           Tier 1 official/primary (A) · Tier 2 established media (B) · Tier 3 social/secondary (C/D)
  Source Reliability    Admiralty letter and meaning
  Raw Information       the text as collected
  Analyst Notes         automatic note (sites, terms, score), editable on the dashboard
  Preliminary Threat Level  High = Act now/Alert, Moderate = Watch, Low = Logged or not flagged; editable
"""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

ET = ZoneInfo("America/New_York")

TEMPLATE_COLUMNS = [  # (header, Excel width)
    ("Date Collected", 17), ("Analyst Initials", 9), ("Collection Phase (General/Industry OR Facility-Specific)", 20),
    ("Tool / Platform Used", 26), ("Source Name", 24), ("Source URL / Citation", 40), ("Source Tier", 22),
    ("Source Reliability", 22), ("Raw Information", 80), ("Analyst Notes", 40),
    ("Preliminary Threat Level (Low, Moderate, High)", 16),
]
EXTRA_COLUMNS = [("Published (ET)", 17), ("Sites", 28), ("Scan ID", 8)]   # kept to the right of the template

PLATFORM = {
    "news": "News RSS", "gdelt": "GDELT DOC 2.0 API", "nws": "National Weather Service API",
    "tfr": "FAA TFR list", "mastodon": "Mastodon public API", "bluesky": "Bluesky API",
    "opendata": "Open Data Buffalo (Socrata API)", "ny511": "511NY API", "adsb": "ADS-B (adsb.lol / airplanes.live)",
    "ais": "AISStream", "youtube": "YouTube Data API", "telegram": "Telegram API", "reddit": "Reddit API", "x": "X API",
    "events": "Ticketmaster Discovery API", "schedules": "NHL / ESPN schedules",
}
TIER = {"A": "Tier 1 – official / primary", "B": "Tier 2 – established media",
        "C": "Tier 3 – social / secondary", "D": "Tier 3 – social / secondary",
        "E": "Tier 3 – social / secondary", "F": "Tier 3 – social / secondary"}
RELIABILITY = {"A": "A – Completely reliable", "B": "B – Usually reliable", "C": "C – Fairly reliable",
               "D": "D – Not usually reliable", "E": "E – Unreliable", "F": "F – Cannot be judged"}
THREAT_LEVEL = {"ACT": "High", "ALERT": "High", "WATCH": "Moderate", "LOG": "Low", "": "Low", None: "Low"}
THREAT_LEVELS = ["Low", "Moderate", "High"]
PHASES = ["General/Industry", "Facility-Specific"]


def tool_for(source: str, via: str = "") -> str:
    return f"ThreatWatch › {via or PLATFORM.get(source, source)}"


def initials(name: str) -> str:
    parts = [p for p in (name or "").replace(".", " ").split() if p]
    return "".join(p[0].upper() for p in parts[:3]) or "TW"


def _et(iso: str | None) -> str:
    return datetime.fromisoformat(iso).astimezone(ET).strftime("%Y-%m-%d %H:%M") if iso else ""


def template_row(r, default_initials: str = "TW") -> list:
    """A collection_log row -> the template's 11 values plus the extras."""
    url = r["url"] or ""
    citation = url if url.startswith("http") else f'{r["source_name"]}, {_et(r["published_at"])[:10]}'
    return [_et(r["collected_at"]), r["initials"] or default_initials, r["phase"] or PHASES[0],
            r["tool"] or tool_for(r["source"]), r["source_name"], citation,
            TIER.get(r["reliability"] or "D", TIER["D"]), RELIABILITY.get(r["reliability"] or "D", RELIABILITY["D"]),
            " ".join((r["title"] or "").split()), r["analyst_notes"] or "", r["threat_level"] or "Low",
            _et(r["published_at"]), r["sites"] or "", r["scan_id"]]


def headers(include_extras: bool = True) -> list[str]:
    return [h for h, _ in TEMPLATE_COLUMNS + (EXTRA_COLUMNS if include_extras else [])]


def analyst_initials() -> str:
    """Initials set on the dashboard (data/ui.json), else from the display name, else TW (automated)."""
    import json

    from .config import DATA_DIR
    try:
        ui = json.loads((DATA_DIR / "ui.json").read_text())
    except Exception:
        ui = {}
    return (ui.get("initials") or initials(ui.get("name") or "Nate")).upper()[:5]   # same default name as the greeting
