"""AIS vessel positions on the Buffalo waterfront via aisstream.io (free API key, websocket).

Each scan listens for `listen_seconds` inside a bounding box over the harbor, Black Rock Canal
and Niagara River entrance. All vessels go to the map's vessel layer. Observations are raised for:
  * navigational status aground (6) / not under command (2) / AIS-SART or emergency (14)
  * a vessel stationary (< 0.5 kn) within 300 m of the International Railway Bridge
  * a vessel moving faster than `harbor_speed_kn` inside the Canalside / Naval Park / Outer Harbor geofences
Small craft often carry no AIS at all, so absence of vessels is not evidence of absence.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from ..config import env
from ..geo import facilities_near, km_between
from ..models import Post
from . import CollectContext, NotConfigured

WS_URL = "wss://stream.aisstream.io/v0/stream"
BOX = [[42.84, -78.94], [42.96, -78.84]]          # [lat, lon] corners — harbor to Black Rock
STATUS = {0: "under way", 1: "at anchor", 2: "not under command", 3: "restricted manoeuvrability",
          5: "moored", 6: "aground", 7: "fishing", 8: "under way sailing", 14: "AIS-SART / emergency"}
HARBOR_FACS = {"canalside", "naval_park", "outer_harbor"}


def parse_message(msg: dict) -> dict | None:
    if msg.get("MessageType") != "PositionReport":
        return None
    md = msg.get("MetaData") or {}
    pr = (msg.get("Message") or {}).get("PositionReport") or {}
    lat = md.get("Latitude", md.get("latitude", pr.get("Latitude")))
    lon = md.get("Longitude", md.get("longitude", pr.get("Longitude")))
    if lat is None or lon is None:
        return None
    return {"mmsi": str(md.get("MMSI", pr.get("UserID", ""))), "name": (md.get("ShipName") or "").strip(),
            "lat": float(lat), "lon": float(lon), "sog": pr.get("Sog"), "cog": pr.get("Cog"),
            "status": pr.get("NavigationalStatus")}


def observations(vessels: dict[str, dict], facilities: list[dict], now: datetime, harbor_speed_kn: float) -> list[Post]:
    bridge = next((f for f in facilities if f["id"] == "intl_rail_bridge"), None)
    out = []
    for v in vessels.values():
        label = v["name"] or f"MMSI {v['mmsi']}"
        near = facilities_near(v["lat"], v["lon"], facilities, 0.2)
        fac = next((f for f in facilities if near and f["id"] == near[0][0]), None)
        where = fac["name"] if fac else "the Buffalo waterfront"
        reasons = []
        if v["status"] in (2, 6, 14):
            reasons.append(f"vessel reports '{STATUS[v['status']]}'" + (" — vessel aground" if v["status"] == 6 else ""))
        if bridge and v["sog"] is not None and v["sog"] < 0.5 and \
                km_between(v["lat"], v["lon"], bridge["lat"], bridge["lon"]) < 0.3 and v["status"] not in (5,):
            reasons.append("stationary vessel within 300 m of the International Railway Bridge")
            where = bridge["name"]
        if fac and fac["id"] in HARBOR_FACS and (v["sog"] or 0) > harbor_speed_kn:
            reasons.append(f"high-speed vessel at {v['sog']:.0f} kn")
        if not reasons:
            continue
        text = f"AIS: {label} near {where}: {'; '.join(reasons)}. Speed {v['sog']} kn."
        out.append(Post(source="ais", source_name="AIS (aisstream.io)", native_id=f"{v['mmsi']}:{now:%Y%m%d%H}",
                        url=f"https://www.marinetraffic.com/en/ais/details/ships/mmsi:{v['mmsi']}",
                        text=text, created_at=now, author=label, reliability="A", is_local=True,
                        lat=v["lat"], lon=v["lon"], engagement={"sog": v["sog"], "status": v["status"]}))
    return out


class AISCollector:
    name = "ais"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        from websockets.sync.client import connect  # optional dependency
        key = env("AISSTREAM_API_KEY")
        if not key:
            raise NotConfigured("AISSTREAM_API_KEY not set in .env")
        listen = float(self.cfg.get("listen_seconds", 60))
        vessels: dict[str, dict] = {}
        with connect(WS_URL, open_timeout=15) as ws:
            ws.send(json.dumps({"APIKey": key, "BoundingBoxes": [BOX], "FilterMessageTypes": ["PositionReport"]}))
            end = time.monotonic() + listen
            while time.monotonic() < end:
                try:
                    raw = ws.recv(timeout=max(0.1, end - time.monotonic()))
                except TimeoutError:
                    break
                msg = json.loads(raw)
                if "error" in msg:
                    raise RuntimeError(f"aisstream: {msg['error']}")
                v = parse_message(msg)
                if v:
                    vessels[v["mmsi"]] = v
        now = datetime.now(timezone.utc)
        for v in vessels.values():
            ctx.store.upsert_track("vessel", v["mmsi"], v["name"], v["lat"], v["lon"],
                                   {"sog": v["sog"], "cog": v["cog"], "status": STATUS.get(v["status"], v["status"])}, now)
        ctx.store.commit()
        return observations(vessels, ctx.facilities.get("facilities", []), now,
                            float(self.cfg.get("harbor_speed_kn", 20)))
