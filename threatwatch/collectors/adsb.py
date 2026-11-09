"""ADS-B aircraft over the facilities — free community feeds (adsb.lol, airplanes.live; same v2 format).

Each scan takes a snapshot of aircraft within ~15 nm of Buffalo. All positions go to the map's aircraft
layer; an observation (which can become a hit) is created only for aircraft that are LOW
(below `max_alt_ft` barometric altitude) and INSIDE a facility geofence (+buffer), excluding the
approach/departure zone around Buffalo Niagara International Airport.

Limits: consumer drones do not broadcast ADS-B; some police and military aircraft don't either.
Snapshots taken twice a day will miss transient overflights; run scans more often around events.
"""
from __future__ import annotations

from datetime import datetime, timezone

import requests

from .. import http

from ..geo import BUF_AIRPORT, facilities_near, km_between
from ..models import Post
from . import CollectContext

FEEDS = ["https://api.adsb.lol/v2/point/{lat}/{lon}/{nm}",
         "https://api.airplanes.live/v2/point/{lat}/{lon}/{nm}"]
CENTER = (42.89, -78.83)
UA = {"User-Agent": "ThreatWatch/0.1 (facility security monitoring)"}


def fetch(lat: float, lon: float, nm: int) -> dict:
    last = None
    for url in FEEDS:
        try:
            r = http.get(url.format(lat=lat, lon=lon, nm=nm), headers=UA, timeout=20, tries=1)  # next feed is the retry
            r.raise_for_status()
            return r.json()
        except Exception as e:  # try the next feed
            last = e
    raise RuntimeError(f"all ADS-B feeds failed: {last}")


def observations(aircraft: list[dict], facilities: list[dict], now: datetime, max_alt_ft: int,
                 buffer_km: float, airport_exclusion_km: float) -> list[Post]:
    out = []
    for a in aircraft:
        lat, lon, alt = a.get("lat"), a.get("lon"), a.get("alt_baro")
        if lat is None or lon is None or not isinstance(alt, (int, float)) or alt > max_alt_ft:
            continue
        if km_between(lat, lon, *BUF_AIRPORT) < airport_exclusion_km:
            continue
        near = facilities_near(lat, lon, facilities, buffer_km)
        if not near:
            continue
        callsign = (a.get("flight") or "").strip() or a.get("r") or a.get("hex", "?")
        heli = a.get("category") == "A7"
        kind = "helicopter" if heli else "low-flying aircraft"
        fac_name = next(f["name"] for f in facilities if f["id"] == near[0][0])
        text = (f"ADS-B: {kind} {callsign} ({a.get('t') or 'type unknown'}, reg {a.get('r') or 'n/a'}) "
                f"at {int(alt)} ft, {a.get('gs', '?')} kt, over {fac_name}.")
        hour = now.strftime("%Y%m%d%H")
        out.append(Post(source="adsb", source_name="ADS-B (adsb.lol)", native_id=f"{a.get('hex')}:{near[0][0]}:{hour}",
                        url=f"https://globe.adsb.lol/?icao={a.get('hex')}", text=text, created_at=now,
                        author=callsign, reliability="A", is_local=True, lat=lat, lon=lon,
                        engagement={"alt_ft": alt, "gs_kt": a.get("gs"), "hex": a.get("hex")}))
    return out


class ADSBCollector:
    name = "adsb"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        body = fetch(CENTER[0], CENTER[1], int(self.cfg.get("radius_nm", 15)))
        now = datetime.now(timezone.utc)
        aircraft = body.get("ac") or body.get("aircraft") or []
        for a in aircraft:
            if a.get("lat") is not None:
                ctx.store.upsert_track("aircraft", a.get("hex", ""), (a.get("flight") or a.get("r") or "").strip(),
                                       a["lat"], a["lon"], {"alt": a.get("alt_baro"), "gs": a.get("gs"),
                                                            "type": a.get("t"), "cat": a.get("category")}, now)
        ctx.store.commit()
        return observations(aircraft, ctx.facilities.get("facilities", []), now,
                            int(self.cfg.get("max_alt_ft", 2000)), float(self.cfg.get("geofence_buffer_km", 0.5)),
                            float(self.cfg.get("airport_exclusion_km", 6)))
