"""Synthetic demo data so the dashboard can be explored before live collection starts.
Writes to data/demo.db only — never mixed with real collection."""
from __future__ import annotations

import random
from zoneinfo import ZoneInfo
from datetime import timedelta

from .config import DATA_DIR, load_facilities, load_keywords, load_sources
from .matcher import Matcher
from .models import Post, utcnow
from .pipeline import process_posts
from .store import Store

DEMO_DB = DATA_DIR / "demo.db"

SAMPLES = [
    ("Bomb threat called in to Buffalo City Hall, Niagara Square being cleared", "bluesky", "Bluesky", "D"),
    ("Buffalo City Hall evacuated after bomb threat, police on scene at Niagara Square", "news", "WGRZ (NBC 2)", "B"),
    ("Multiple fights and a large juvenile crowd at Canalside, police called", "reddit", "r/Buffalo", "D"),
    ("Teens fighting near Canalside again tonight, someone said shots fired", "bluesky", "Bluesky", "D"),
    ("Police respond to reports of shots fired near Canalside; no injuries", "news", "WKBW (7 News)", "B"),
    ("Drone spotted flying over Highmark Stadium during Bills game", "bluesky", "Bluesky", "D"),
    ("Unauthorized drone grounded near Highmark Stadium, Orchard Park police say", "news", "WIVB (News 4)", "B"),
    ("Vessel capsized near the Outer Harbor, Coast Guard responding to water rescue", "nws", "NWS LEZ020", "A"),
    ("Boating accident near Gallagher Beach, two pulled from water", "news", "WGRZ (NBC 2)", "B"),
    ("Protest planned at Niagara Square Saturday over county budget", "news", "Buffalo News", "B"),
    ("Large protest at Niagara Square, counter-protesters arriving", "bluesky", "Bluesky", "D"),
    ("Overcrowding at KeyBank Center gates before Sabres game, people getting pushed", "reddit", "r/sabres", "D"),
    ("Medical emergency inside KeyBank Center during concert", "bluesky", "Bluesky", "D"),
    ("Vandalism and graffiti found on the Broadway Market overnight", "news", "WIVB (News 4)", "B"),
    ("Suspicious package reported outside the Federal Courthouse in Buffalo, area closed", "news", "WKBW (7 News)", "B"),
    ("Suspicious package at Jackson Courthouse Buffalo turned out to be a lunch bag", "bluesky", "Bluesky", "D"),
    ("Stabbing on Chippewa Street early Sunday, one hospitalized", "news", "Buffalo News", "B"),
    ("Brawl on Chippewa St outside the bars, police everywhere", "reddit", "r/Buffalo", "D"),
    ("Antisemitic graffiti reported near the JCC on Delaware Ave in Buffalo", "news", "WGRZ (NBC 2)", "B"),
    ("Car crash on Fuhrmann Blvd by the Outer Harbor, lost control in fog", "reddit", "r/Buffalo", "D"),
    ("Low visibility and fog on Lake Erie near Buffalo, gale warning issued", "nws", "NWS LEZ020", "A"),
    ("Trespassing at the Central Terminal tower again, Buffalo police called", "reddit", "r/Buffalo", "D"),
    ("Rail disruption at the International Railway Bridge, Black Rock crossing closed", "news", "WIVB (News 4)", "B"),
    ("Disorderly conduct arrests outside Sahlen Field after Bisons fireworks night", "news", "WKBW (7 News)", "B"),
    ("Assault reported in Cazenovia Park, Buffalo police investigating", "news", "Buffalo News", "B"),
    ("Crowd panic at RiverWorks concert after loud bang, people running", "bluesky", "Bluesky", "D"),
    ("Fight outside the Board of Elections in Buffalo during early voting", "bluesky", "Bluesky", "D"),
    ("Politically motivated protest at Erie County Board of Elections planned", "reddit", "r/WNY", "D"),
    ("AEROCINE Films crew filming with drone over the Naval Park in Buffalo", "bluesky", "Bluesky", "D"),
    ("Shooting reported on the East Side of Buffalo near MLK Park", "news", "WGRZ (NBC 2)", "B"),
    ("Youth violence at MLK Park in Buffalo after basketball tournament", "reddit", "r/Buffalo", "D"),
    ("Hit and run near the Convention Center in Buffalo, pedestrian injured", "news", "WIVB (News 4)", "B"),
]


def build_demo() -> str:
    if DEMO_DB.exists():
        DEMO_DB.unlink()
    store = Store(DEMO_DB)
    matcher = Matcher(load_facilities(), load_keywords())
    rnd = random.Random(7)
    now = utcnow()
    posts = []
    for i, (text, src, name, rel) in enumerate(SAMPLES):
        age = timedelta(hours=rnd.uniform(0.5, 160))
        posts.append(Post(src, name, f"demo-{i}", "", text, now - age,
                          author="demo", reliability=rel, is_local=src in ("news", "nws", "reddit")))
    # pairs that describe the same incident land close together so corroboration fires
    posts[1].created_at = posts[0].created_at + timedelta(minutes=40)
    posts[4].created_at = posts[3].created_at + timedelta(minutes=55)
    posts[6].created_at = posts[5].created_at + timedelta(minutes=70)
    facs = load_facilities()["facilities"]
    _demo_events(store, facs, now)
    posts += _demo_located(now)
    posts += _demo_sensors(store, facs, now, rnd)

    sources = load_sources()
    sources.setdefault("scan", {})["corroboration_window_hours"] = 12
    scan_id = store.begin_scan(now - timedelta(minutes=2))
    log: list = []
    process_posts(posts, store, matcher, sources, log=log)
    for r in log:                      # spread collection times like real scans
        r["collected_at"] = max(r["published_at"], (now - timedelta(hours=rnd.uniform(0, 3))).isoformat())
    per = {}
    for r in log:
        d = per.setdefault(r["source"], {"source": r["source"], "state": "ok", "items": 0, "new": 0, "flagged": 0,
                                         "seconds": round(rnd.uniform(.5, 20), 1), "error": ""})
        d["items"] += 1
        d["new"] += 1
        d["flagged"] += bool(r["level"])
    store.log_collection(scan_id, log, list(per.values()))
    store.log_scan(now - timedelta(minutes=2), len(posts), len(posts), 0, 0, {},
                   {"per_source": {"demo": len(posts)}, "not_configured": {}}, scan_id=scan_id)
    return str(DEMO_DB)


def _demo_events(store: Store, facs: list[dict], now) -> None:
    from .collectors.events import parse_event
    et = ZoneInfo("America/New_York")
    today = now.astimezone(et).replace(minute=0, second=0, microsecond=0)
    sample = [
        ("Buffalo Sabres vs. Toronto Maple Leafs", "KeyBank Center", 42.8750, -78.8764, today.replace(hour=19), "Sports"),
        ("Buffalo Bills vs. Miami Dolphins", "Highmark Stadium", 42.7745, -78.7880,
         (today + timedelta(days=5)).replace(hour=13), "Sports"),
        ("Fall Concert Series", "Buffalo RiverWorks", 42.8692, -78.8655, (today + timedelta(days=3)).replace(hour=20), "Music"),
        ("Bisons Fireworks Night", "Sahlen Field", 42.8805, -78.8740, (today - timedelta(days=2)).replace(hour=19), "Sports"),
        ("Tech Expo 2026", "Buffalo Niagara Convention Center", 42.8867, -78.8772,
         (today + timedelta(days=8)).replace(hour=10), "Miscellaneous"),
        ("Sabres vs. Boston Bruins", "KeyBank Center", 42.8750, -78.8764, (today + timedelta(days=4)).replace(hour=19), "Sports"),
    ]
    for i, (name, venue, lat, lon, when, seg) in enumerate(sample):
        e = parse_event({"id": f"demo{i}", "name": name, "url": "https://www.ticketmaster.com/",
                         "dates": {"start": {"dateTime": when.astimezone(ZoneInfo("UTC")).isoformat().replace("+00:00", "Z")}},
                         "classifications": [{"segment": {"name": seg}}],
                         "_embedded": {"venues": [{"name": venue, "location": {"latitude": str(lat), "longitude": str(lon)}}]}},
                        facs)
        if e:
            store.upsert_event(e)
    store.commit()


def _demo_located(now) -> list[Post]:
    from .collectors.ny511 import to_post as ny511_post
    from .collectors.opendata import to_post as od_post
    et = ZoneInfo("America/New_York")
    loc = lambda h: (now - timedelta(hours=h)).astimezone(et).strftime("%Y-%m-%dT%H:%M:%S.000")
    recs = [
        {"case_number": "D-1001", "incident_datetime": loc(30), "incident_type_primary": "ASSAULT",
         "parent_incident_type": "Assault", "address_1": "200 Block Chippewa St", "neighborhood": "Central",
         "latitude": "42.8930", "longitude": "-78.8748"},
        {"case_number": "D-1002", "incident_datetime": loc(52), "incident_type_primary": "ROBBERY",
         "parent_incident_type": "Robbery", "address_1": "100 Block Main St", "neighborhood": "Central",
         "latitude": "42.8790", "longitude": "-78.8775"},
        {"case_number": "D-1003", "incident_datetime": loc(70), "incident_type_primary": "BURGLARY",
         "parent_incident_type": "Breaking & Entering", "address_1": "900 Block Broadway", "neighborhood": "Broadway Fillmore",
         "latitude": "42.8905", "longitude": "-78.8352"},
    ]
    out = [p for p in (od_post(r) for r in recs) if p]
    evs = [
        {"ID": "D-511-1", "EventType": "accident", "EventSubType": "Crash", "RoadwayName": "NY 5 (Skyway)",
         "Description": "Crash with injuries on NY 5 near Fuhrmann Blvd, right lane blocked",
         "LastUpdated": int((now - timedelta(hours=5)).timestamp()), "Latitude": 42.8660, "Longitude": -78.8720},
        {"ID": "D-511-2", "EventType": "closures", "RoadwayName": "Niagara St",
         "Description": "Road closed for police activity near Black Rock rail bridge", "IsFullClosure": True,
         "LastUpdated": int((now - timedelta(hours=20)).timestamp()), "Latitude": 42.9318, "Longitude": -78.9050},
    ]
    out += [p for p in (ny511_post(e) for e in evs) if p]
    return out


def _demo_sensors(store: Store, facs: list[dict], now, rnd: random.Random) -> list[Post]:
    from .collectors.adsb import observations as adsb_obs
    from .collectors.ais import observations as ais_obs
    aircraft = [{"hex": f"a{rnd.randrange(16**5):05x}", "flight": f"DAL{rnd.randint(100, 999)}", "r": "N" + str(rnd.randint(100, 999)),
                 "t": "A321", "alt_baro": rnd.randint(4000, 12000), "gs": rnd.randint(180, 320),
                 "lat": 42.88 + rnd.uniform(-0.18, 0.18), "lon": -78.83 + rnd.uniform(-0.25, 0.25), "category": "A3"}
                for _ in range(14)]
    aircraft += [
        {"hex": "a1b2c3", "flight": "N912HP", "r": "N912HP", "t": "EC35", "alt_baro": 1150, "gs": 22,
         "lat": 42.7752, "lon": -78.7871, "category": "A7"},                       # helicopter over Highmark
        {"hex": "a4d5e6", "flight": "", "r": "N44KB", "t": "C172", "alt_baro": 1450, "gs": 85,
         "lat": 42.8771, "lon": -78.8790, "category": "A1"},                       # low pass over Canalside
    ]
    for a in aircraft:
        store.upsert_track("aircraft", a["hex"], a["flight"] or a["r"], a["lat"], a["lon"],
                           {"alt": a["alt_baro"], "gs": a["gs"], "type": a["t"], "cat": a["category"]}, now)
    vessels = {
        "367001001": {"mmsi": "367001001", "name": "MISS BUFFALO II", "lat": 42.8772, "lon": -78.8820, "sog": 6.1, "cog": 200, "status": 0},
        "367001002": {"mmsi": "367001002", "name": "SPIRIT OF BUFFALO", "lat": 42.8781, "lon": -78.8835, "sog": 0.0, "cog": 0, "status": 5},
        "367001003": {"mmsi": "367001003", "name": "RIVER DAWN", "lat": 42.9326, "lon": -78.9068, "sog": 0.1, "cog": 0, "status": 0},
        "367001004": {"mmsi": "367001004", "name": "FAST LANE", "lat": 42.8655, "lon": -78.8760, "sog": 27.0, "cog": 15, "status": 0},
        "316001005": {"mmsi": "316001005", "name": "CCGS GRIFFON", "lat": 42.8710, "lon": -78.8950, "sog": 9.5, "cog": 300, "status": 0},
        "367001006": {"mmsi": "367001006", "name": "", "lat": 42.9000, "lon": -78.9030, "sog": 3.2, "cog": 350, "status": 0},
    }
    for v in vessels.values():
        store.upsert_track("vessel", v["mmsi"], v["name"], v["lat"], v["lon"],
                           {"sog": v["sog"], "cog": v["cog"], "status": v["status"]}, now)
    store.commit()
    return adsb_obs(aircraft, facs, now - timedelta(minutes=40), 2000, 0.5, 6) + \
        ais_obs(vessels, facs, now - timedelta(minutes=25), 20)
