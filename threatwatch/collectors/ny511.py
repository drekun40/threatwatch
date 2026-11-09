"""511NY traffic events (crashes, closures, incidents). Free developer key: 511ny.org/developers.

The 511NY schema is read tolerantly (field names case-insensitive; dates as Unix seconds,
/Date(ms)/ or ISO) so minor format changes don't break collection. Only events inside or near
a facility geofence are kept. Routine construction is skipped unless configured otherwise.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import requests

from .. import http

from ..config import env
from ..geo import facilities_near
from ..models import Post, utcnow
from . import CollectContext, NotConfigured

URL = "https://511ny.org/api/getevents"


def _get(d: dict, *names, default=None):
    low = {k.lower(): v for k, v in d.items()}
    for n in names:
        if n.lower() in low and low[n.lower()] not in (None, ""):
            return low[n.lower()]
    return default


def parse_time(v) -> datetime | None:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
        n = int(v)
        return datetime.fromtimestamp(n / 1000 if n > 10**11 else n, tz=timezone.utc)
    m = re.search(r"/Date\((\d+)", str(v))
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def to_post(ev: dict) -> Post | None:
    try:
        lat, lon = float(_get(ev, "Latitude", "lat")), float(_get(ev, "Longitude", "lon", "lng"))
    except (TypeError, ValueError):
        return None
    etype = str(_get(ev, "EventType", "Type", default="event"))
    sub = str(_get(ev, "EventSubType", "SubType", default=""))
    road = _get(ev, "RoadwayName", "Roadway", default="")
    desc = _get(ev, "Description", "Comment", default="")
    when = parse_time(_get(ev, "LastUpdated", "Reported", "StartDate", "StartTime")) or utcnow()
    closure = _get(ev, "IsFullClosure", "FullClosure", default=False)
    text = f"511NY {etype}{' / ' + sub if sub else ''} on {road}: {desc}" + (" Full closure." if str(closure).lower() == "true" else "")
    eid = str(_get(ev, "ID", "Id", "EventId", default=f"{lat},{lon},{etype}"))
    return Post(source="ny511", source_name="511NY", native_id=f"{eid}:{when.isoformat()[:13]}",
                url="https://511ny.org/", text=text, created_at=when, author="NYSDOT", reliability="A",
                is_local=True, lat=lat, lon=lon,
                engagement={"type": etype, "subtype": sub, "severity": _get(ev, "Severity", default="")})


class NY511Collector:
    name = "ny511"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        key = env("NY511_API_KEY")
        if not key:
            raise NotConfigured("NY511_API_KEY not set in .env")
        r = http.get(URL, params={"key": key, "format": "json"}, timeout=30)
        r.raise_for_status()
        data = r.json()
        events = data if isinstance(data, list) else _get(data, "events", "Events", default=[])
        skip = [s.lower() for s in self.cfg.get("skip_types", ["construction", "roadwork", "special event"])]
        facs = ctx.facilities.get("facilities", [])
        buffer_km = float(self.cfg.get("geofence_buffer_km", 0.4))
        out = []
        for ev in events:
            p = to_post(ev)
            if not p or p.created_at < ctx.since:
                continue
            if any(s in p.engagement.get("type", "").lower() for s in skip):
                continue
            if facilities_near(p.lat, p.lon, facs, buffer_km):
                out.append(p)
        return out
