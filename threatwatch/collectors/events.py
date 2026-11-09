"""Ticketmaster Discovery API — scheduled games, concerts and shows near the monitored venues.
Free key: developer.ticketmaster.com. Events don't create hits; they give crowd context:
the map/cards show event days, and threat hits at a venue within ±6 h of an event get a score boost."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import requests

from .. import http

from ..config import env
from ..geo import nearest_facility
from ..models import Post, utcnow
from . import CollectContext, NotConfigured

URL = "https://app.ticketmaster.com/discovery/v2/events.json"


def parse_event(ev: dict, facilities) -> dict | None:
    venues = (ev.get("_embedded") or {}).get("venues") or [{}]
    v = venues[0]
    loc = v.get("location") or {}
    try:
        lat, lon = float(loc["latitude"]), float(loc["longitude"])
    except (KeyError, TypeError, ValueError):
        return None
    start = (ev.get("dates") or {}).get("start") or {}
    if start.get("dateTime"):
        when = datetime.fromisoformat(start["dateTime"].replace("Z", "+00:00"))
    elif start.get("localDate"):
        when = datetime.fromisoformat(start["localDate"] + "T19:00:00-04:00").astimezone(timezone.utc)
    else:
        return None
    near = nearest_facility(lat, lon, facilities, max_km=1.0)
    if not near:
        return None
    seg = ((ev.get("classifications") or [{}])[0].get("segment") or {}).get("name", "")
    return {"id": f"tm:{ev['id']}", "source": "ticketmaster", "name": ev.get("name", "Event"),
            "venue": v.get("name", ""), "facility_id": near[0], "start_at": when.isoformat(),
            "url": ev.get("url", ""), "lat": lat, "lon": lon, "info": {"segment": seg}}


class EventsCollector:
    name = "events"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        key = env("TICKETMASTER_API_KEY")
        if not key:
            raise NotConfigured("TICKETMASTER_API_KEY not set in .env")
        now = utcnow()
        params = {"apikey": key, "latlong": "42.88,-78.84", "radius": 25, "unit": "miles", "size": 200,
                  "sort": "date,asc",
                  "startDateTime": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "endDateTime": (now + timedelta(days=int(self.cfg.get("days_ahead", 21)))).strftime("%Y-%m-%dT%H:%M:%SZ")}
        facs = ctx.facilities.get("facilities", [])
        stored = 0
        for page in range(int(self.cfg.get("max_pages", 3))):
            params["page"] = page
            r = http.get(URL, params=params, timeout=30)
            r.raise_for_status()
            body = r.json()
            for ev in (body.get("_embedded") or {}).get("events", []):
                e = parse_event(ev, facs)
                if e:
                    ctx.store.upsert_event(e)
                    stored += 1
            if page + 1 >= (body.get("page") or {}).get("totalPages", 1):
                break
        ctx.store.commit()
        ctx.store.set_state("events_last_count", stored)
        return []   # context only — no posts
