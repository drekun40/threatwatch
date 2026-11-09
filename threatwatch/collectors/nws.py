"""National Weather Service active alerts (Erie County + Lake Erie marine zone)."""
from __future__ import annotations

from datetime import datetime, timezone

import requests

from .. import http

from ..models import Post
from . import CollectContext

UA = "ThreatWatch/0.1 (facility security monitoring)"


class NWSCollector:
    name = "nws"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        posts = []
        for zone in self.cfg.get("zones", []):
            r = http.get("https://api.weather.gov/alerts/active", params={"zone": zone},
                             headers={"User-Agent": UA, "Accept": "application/geo+json"}, timeout=20)
            r.raise_for_status()
            for f in r.json().get("features", []):
                p = f.get("properties", {})
                sent = p.get("sent") or p.get("effective")
                when = datetime.fromisoformat(sent) if sent else datetime.now(timezone.utc)
                text = " ".join(filter(None, [p.get("event"), p.get("headline"),
                                              p.get("areaDesc"), p.get("description")]))
                # human-readable NWS pages (the API URL is JSON): marine zone page or Buffalo point forecast
                page = (f"https://forecast.weather.gov/shmrn.php?mz={zone.lower()}" if zone.upper().startswith("LE")
                        else "https://forecast.weather.gov/MapClick.php?lat=42.8864&lon=-78.8784")
                posts.append(Post(
                    source="nws", source_name=f"NWS {zone}", native_id=p.get("id", f.get("id", "")),
                    url=page, text=text,
                    created_at=when.astimezone(timezone.utc), author=p.get("senderName", "NWS"),
                    reliability="A", is_local=True,
                    engagement={"severity": p.get("severity"), "urgency": p.get("urgency")}))
        return posts
