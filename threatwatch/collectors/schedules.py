"""Free team schedules (no key) + your own event list, for crowd context at the venues.

  Sabres home games -> KeyBank Center      NHL official API (api-web.nhle.com)
  Bills home games  -> Highmark Stadium    ESPN public team-schedule feed
  config/events.yaml                       events you add yourself (concerts, festivals, rallies...)

Like Ticketmaster, these don't create hits: they fill "Upcoming events", draw blue rings on the map,
and add the event-day bonus to threat items at that venue within ±6 h of start.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests

from .. import http
import yaml

from ..config import CONFIG_DIR
from ..models import Post, utcnow
from . import CollectContext

log = logging.getLogger("threatwatch")
ET = ZoneInfo("America/New_York")
UA = {"User-Agent": "ThreatWatch/0.1 (facility security monitoring)"}
EVENTS_FILE = CONFIG_DIR / "events.yaml"

NHL_URL = "https://api-web.nhle.com/v1/club-schedule-season/{team}/now"
ESPN_URL = "https://site.api.espn.com/apis/site/v2/sports/{sport}/{league}/teams/{team}/schedule"

TEAMS = [
    {"key": "sabres", "kind": "nhl", "team": "BUF", "facility_id": "keybank_center", "venue": "KeyBank Center"},
    {"key": "bills", "kind": "espn", "sport": "football", "league": "nfl", "team": "buf",
     "facility_id": "highmark_stadium", "venue": "Highmark Stadium"},
]


def _iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def parse_nhl(body: dict, team: dict, start: datetime, end: datetime) -> list[dict]:
    out = []
    for g in body.get("games", []):
        if (g.get("homeTeam") or {}).get("abbrev") != team["team"] or not g.get("startTimeUTC"):
            continue
        when = _iso(g["startTimeUTC"])
        if not (start <= when <= end):
            continue
        away = g.get("awayTeam") or {}
        opp = ((away.get("placeName") or {}).get("default") or away.get("city") or away.get("abbrev") or "TBD")
        if isinstance(opp, dict):
            opp = opp.get("default", "TBD")
        venue = g.get("venue")
        venue = venue.get("default") if isinstance(venue, dict) else (venue or team["venue"])
        link = g.get("gameCenterLink") or ""
        kind = {1: "Preseason: ", 3: "Playoffs: "}.get(g.get("gameType"), "")
        out.append({"id": f"nhl:{g.get('id')}", "source": "NHL", "name": f"{kind}Sabres vs. {opp}",
                    "venue": venue, "facility_id": team["facility_id"], "start_at": when.isoformat(),
                    "url": ("https://www.nhl.com" + link) if link.startswith("/") else (link or "https://www.nhl.com/sabres/schedule"),
                    "lat": None, "lon": None, "info": {"game_type": g.get("gameType")}})
    return out


def parse_espn(body: dict, team: dict, start: datetime, end: datetime) -> list[dict]:
    out = []
    for ev in body.get("events", []):
        comp = (ev.get("competitions") or [{}])[0]
        home = next((c for c in comp.get("competitors", []) if c.get("homeAway") == "home"), {})
        if (home.get("team") or {}).get("abbreviation", "").lower() != team["team"]:
            continue
        if comp.get("neutralSite"):
            continue
        try:
            when = _iso(ev.get("date") or comp.get("date"))
        except (TypeError, ValueError):
            continue
        if not (start <= when <= end):
            continue
        away = next((c for c in comp.get("competitors", []) if c.get("homeAway") == "away"), {})
        opp = (away.get("team") or {}).get("displayName") or "TBD"
        link = next((l.get("href") for l in ev.get("links", []) if l.get("href")), "") or \
            f"https://www.espn.com/{team['league']}/game/_/gameId/{ev.get('id')}"
        out.append({"id": f"espn:{ev.get('id')}", "source": "ESPN", "name": f"Bills vs. {opp}",
                    "venue": (comp.get("venue") or {}).get("fullName") or team["venue"],
                    "facility_id": team["facility_id"], "start_at": when.isoformat(), "url": link,
                    "lat": None, "lon": None, "info": {}})
    return out


def load_manual(facilities: list[dict]) -> list[dict]:
    """config/events.yaml: - {name: ..., site: canalside, start: "2026-10-25 19:00", url: ...}"""
    if not EVENTS_FILE.exists():
        return []
    ids = {f["id"] for f in facilities}
    out = []
    for i, e in enumerate((yaml.safe_load(EVENTS_FILE.read_text(encoding="utf-8")) or {}).get("events", []) or []):
        try:
            when = datetime.strptime(str(e["start"]), "%Y-%m-%d %H:%M").replace(tzinfo=ET).astimezone(timezone.utc)
        except (KeyError, ValueError):
            log.warning("events.yaml entry %d skipped: start must look like 2026-10-25 19:00", i + 1)
            continue
        if e.get("site") not in ids:
            log.warning("events.yaml entry %d skipped: unknown site %r", i + 1, e.get("site"))
            continue
        out.append({"id": f"manual:{i}:{e['site']}:{when.isoformat()}", "source": "Manual", "name": e.get("name", "Event"),
                    "venue": e.get("venue", ""), "facility_id": e["site"], "start_at": when.isoformat(),
                    "url": e.get("url", ""), "lat": None, "lon": None, "info": {}})
    return out


class SchedulesCollector:
    name = "schedules"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        now = utcnow()
        start, end = now - timedelta(hours=6), now + timedelta(days=int(self.cfg.get("days_ahead", 14)))
        events, failures = [], []
        for team in TEAMS:
            if team["key"] not in self.cfg.get("teams", ["sabres", "bills"]):
                continue
            try:
                if team["kind"] == "nhl":
                    r = http.get(NHL_URL.format(team=team["team"]), headers=UA, timeout=20)
                    r.raise_for_status()
                    events += parse_nhl(r.json(), team, start, end)
                else:
                    r = http.get(ESPN_URL.format(**team), headers=UA, timeout=20)
                    r.raise_for_status()
                    events += parse_espn(r.json(), team, start, end)
            except Exception as e:
                failures.append(f"{team['key']}: {e}")
        # manual list is rebuilt each scan so deleted entries disappear
        ctx.store.conn.execute("DELETE FROM events WHERE source='Manual'")
        events += load_manual(ctx.facilities.get("facilities", []))
        for e in events:
            ctx.store.upsert_event(e)
        ctx.store.commit()
        ctx.store.set_state("schedules_last_count", len(events))
        if failures and len(failures) == len([t for t in TEAMS if t["key"] in self.cfg.get("teams", ["sabres", "bills"])]):
            raise RuntimeError("team schedules unavailable — " + "; ".join(failures)[:250])
        for f in failures:
            log.warning("schedules: %s", f)
        return []
