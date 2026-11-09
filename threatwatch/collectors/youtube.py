"""YouTube Data API v3 — videos and livestreams geotagged near the facilities, plus keyword searches.
Free key (Google Cloud console -> YouTube Data API v3). Quota: 10,000 units/day, each search = 100,
so the defaults (~10 searches per scan, 2 scans/day) use about 2,000 units/day."""
from __future__ import annotations

from datetime import datetime
from html import unescape

import requests

from .. import http

from ..config import env
from ..models import Post
from . import CollectContext, NotConfigured

URL = "https://www.googleapis.com/youtube/v3/search"

# Location clusters: one geo search covers several nearby facilities.
DEFAULT_AREAS = [
    {"name": "Downtown / waterfront", "lat": 42.8820, "lon": -78.8760, "radius": "2km"},
    {"name": "Outer Harbor", "lat": 42.8640, "lon": -78.8730, "radius": "1500m"},
    {"name": "East Side (MLK / Broadway / Terminal)", "lat": 42.8950, "lon": -78.8360, "radius": "1500m"},
    {"name": "Highmark Stadium", "lat": 42.7745, "lon": -78.7880, "radius": "1500m"},
    {"name": "Black Rock / rail bridge", "lat": 42.9330, "lon": -78.9060, "radius": "1500m"},
    {"name": "South Buffalo / Caz Park", "lat": 42.8478, "lon": -78.8044, "radius": "1500m"},
    {"name": "Getzville JCC", "lat": 43.0236, "lon": -78.7647, "radius": "1km"},
]


def item_to_post(it: dict, area: dict | None) -> Post | None:
    vid = (it.get("id") or {}).get("videoId")
    sn = it.get("snippet") or {}
    if not vid:
        return None
    live = sn.get("liveBroadcastContent", "none")
    text = unescape(f"{sn.get('title', '')}. {sn.get('description', '')}")
    if live == "live":
        text = "[LIVE] " + text
    return Post(source="youtube", source_name=f"YouTube: {sn.get('channelTitle', '')}"[:80],
                native_id=vid, url=f"https://www.youtube.com/watch?v={vid}", text=text,
                created_at=datetime.fromisoformat(sn["publishedAt"].replace("Z", "+00:00")),
                author=sn.get("channelTitle", ""), reliability="D",
                is_local=area is not None,
                lat=area["lat"] if area else None, lon=area["lon"] if area else None,
                engagement={"live": live, "area": area["name"] if area else ""})


class YouTubeCollector:
    name = "youtube"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def _search(self, key: str, since, **params) -> list[dict]:
        r = http.get(URL, timeout=30, params={
            "key": key, "part": "snippet", "type": "video", "order": "date", "maxResults": 50,
            "publishedAfter": since.strftime("%Y-%m-%dT%H:%M:%SZ"), **params})
        r.raise_for_status()
        return r.json().get("items", [])

    def collect(self, ctx: CollectContext) -> list[Post]:
        key = env("YOUTUBE_API_KEY")
        if not key:
            raise NotConfigured("YOUTUBE_API_KEY not set in .env")
        out, seen = [], set()
        for area in self.cfg.get("areas", DEFAULT_AREAS):
            for it in self._search(key, ctx.since, location=f"{area['lat']},{area['lon']}",
                                   locationRadius=area["radius"]):
                p = item_to_post(it, area)
                if p and p.native_id not in seen:
                    seen.add(p.native_id)
                    # geotag is the area centre, not the exact spot: drop coords so matching
                    # relies on text (facility names) rather than a guessed point
                    p.lat = p.lon = None
                    out.append(p)
        for q in self.cfg.get("queries", ["Buffalo NY shooting", "Buffalo NY police", "Canalside Buffalo",
                                          "Highmark Stadium"]):
            for it in self._search(key, ctx.since, q=q, regionCode="US"):
                p = item_to_post(it, None)
                if p and p.native_id not in seen:
                    seen.add(p.native_id)
                    out.append(p)
        return out
