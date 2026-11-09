"""Open Data Buffalo — Buffalo Police crime incidents (Socrata dataset d6g9-xbgu). Free; app token optional.

Only incidents inside a facility geofence are kept, so routine citywide crime doesn't flood the feed.
BPD describes this data as preliminary and it is usually published with a lag of a day or more,
so this source has its own longer lookback (sources.yaml -> opendata.lookback_hours).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests

from .. import http

from ..config import env
from ..geo import facilities_near
from ..models import Post, utcnow
from . import CollectContext

URL = "https://data.buffalony.gov/resource/d6g9-xbgu.json"
ET = ZoneInfo("America/New_York")


def to_post(rec: dict) -> Post | None:
    try:
        lat, lon = float(rec["latitude"]), float(rec["longitude"])
    except (KeyError, TypeError, ValueError):
        return None
    when = datetime.fromisoformat(rec["incident_datetime"][:19]).replace(tzinfo=ET).astimezone(timezone.utc)
    kind = rec.get("incident_type_primary", "Incident").title()
    parent = rec.get("parent_incident_type", "")
    where = ", ".join(x for x in [rec.get("address_1", ""), rec.get("neighborhood", "")] if x)
    text = f"Buffalo Police reported incident: {kind}" + (f" ({parent})" if parent and parent.lower() != kind.lower() else "") \
           + f" at {where}. {rec.get('incident_description', '') or ''}".rstrip()
    case = rec.get("case_number", f"{lat},{lon},{rec['incident_datetime']}")
    return Post(source="opendata", source_name="Buffalo Police (Open Data)", native_id=str(case),
                url=f"https://data.buffalony.gov/resource/d6g9-xbgu.json?case_number={case}",
                text=text, created_at=when, author="BPD", reliability="A", is_local=True,
                lat=lat, lon=lon, engagement={"type": kind, "district": rec.get("police_district")})


class OpenDataCollector:
    name = "opendata"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        since = utcnow() - timedelta(hours=float(self.cfg.get("lookback_hours", 96)))
        since_local = since.astimezone(ET).strftime("%Y-%m-%dT%H:%M:%S")
        headers = {"X-App-Token": env("SOCRATA_APP_TOKEN")} if env("SOCRATA_APP_TOKEN") else {}
        r = http.get(URL, timeout=30, headers=headers, params={
            "$where": f"incident_datetime > '{since_local}'", "$order": "incident_datetime DESC",
            "$limit": 5000})
        r.raise_for_status()
        facs = ctx.facilities.get("facilities", [])
        buffer_km = float(self.cfg.get("geofence_buffer_km", 0.1))
        out = []
        for rec in r.json():
            p = to_post(rec)
            if p and facilities_near(p.lat, p.lon, facs, buffer_km):
                out.append(p)
        return out
