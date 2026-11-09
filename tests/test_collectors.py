"""Collector tests with recorded-shape API responses (no network). Each test feeds the collector the
JSON structure the real service returns and checks the posts/events/tracks that come out."""
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from threatwatch.collectors import CollectContext, NotConfigured
from threatwatch.config import load_facilities, load_keywords, load_sources
from threatwatch.matcher import Matcher
from threatwatch.store import Store

NOW = datetime.now(timezone.utc)


class FakeResp:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.fixture
def ctx(tmp_path):
    return CollectContext(load_facilities(), load_keywords(), load_sources(), Store(tmp_path / "c.db"),
                          NOW - timedelta(hours=24))


@pytest.fixture
def matcher():
    return Matcher(load_facilities(), load_keywords())


def cfg(name):
    return load_sources()["sources"][name]


# ---------------------------------------------------------------- Open Data Buffalo
def test_opendata(monkeypatch, ctx, matcher):
    from threatwatch.collectors import opendata
    from zoneinfo import ZoneInfo
    t = (NOW - timedelta(hours=5)).astimezone(ZoneInfo("America/New_York")).strftime("%Y-%m-%dT%H:%M:%S.000")
    recs = [  # same keys as the live dataset (verified Oct 2026)
        {"case_number": "262921050", "incident_datetime": t, "incident_type_primary": "ASSAULT",
         "parent_incident_type": "Assault", "address_1": "250 Chippewa St", "neighborhood": "Central",
         "latitude": "42.8928", "longitude": "-78.8745", "police_district": "District B"},
        {"case_number": "262920943", "incident_datetime": t, "incident_type_primary": "BURGLARY",
         "parent_incident_type": "Breaking & Entering", "address_1": "38 Schreck Ave",
         "latitude": "42.926", "longitude": "-78.816"},           # not near any facility -> dropped
        {"case_number": "x", "incident_datetime": t, "incident_type_primary": "THEFT"},  # no coords -> dropped
    ]
    seen = {}
    monkeypatch.setattr(opendata.requests, "get", lambda url, **kw: seen.update(kw) or FakeResp(recs))
    posts = opendata.OpenDataCollector(cfg("opendata")).collect(ctx)
    assert len(posts) == 1 and posts[0].reliability == "A"
    assert "incident_datetime >" in seen["params"]["$where"]
    m = matcher.match(posts[0])
    assert m.facilities == ["entertainment_district"] and "weapons_violence" in m.threat_terms


# ---------------------------------------------------------------- 511NY
@pytest.mark.parametrize("ts", [int((NOW - timedelta(hours=1)).timestamp()),
                                f"/Date({int((NOW - timedelta(hours=1)).timestamp() * 1000)})/",
                                (NOW - timedelta(hours=1)).isoformat()])
def test_ny511_formats(monkeypatch, ctx, matcher, ts):
    from threatwatch.collectors import ny511
    monkeypatch.setenv("NY511_API_KEY", "k")
    evs = [{"ID": "NYSDOT-1", "EventType": "accident", "RoadwayName": "NY 5", "LastUpdated": ts,
            "Description": "Crash, right lane blocked", "Latitude": 42.866, "Longitude": -78.872},
           {"id": "2", "eventtype": "construction", "roadwayname": "Fuhrmann", "lastupdated": ts,
            "description": "Paving", "latitude": 42.865, "longitude": -78.873},          # skipped type
           {"ID": "3", "EventType": "accident", "LastUpdated": ts, "Description": "Crash in Albany",
            "Latitude": 42.65, "Longitude": -73.75}]                                       # far away
    monkeypatch.setattr(ny511.requests, "get", lambda url, **kw: FakeResp(evs))
    posts = ny511.NY511Collector(cfg("ny511")).collect(ctx)
    assert len(posts) == 1
    assert abs((posts[0].created_at - (NOW - timedelta(hours=1))).total_seconds()) < 5
    assert matcher.match(posts[0]).facilities == ["outer_harbor"]


def test_ny511_needs_key(monkeypatch, ctx):
    from threatwatch.collectors import ny511
    monkeypatch.delenv("NY511_API_KEY", raising=False)
    with pytest.raises(NotConfigured):
        ny511.NY511Collector(cfg("ny511")).collect(ctx)


# ---------------------------------------------------------------- Ticketmaster
def test_events(monkeypatch, ctx):
    from threatwatch.collectors import events
    monkeypatch.setenv("TICKETMASTER_API_KEY", "k")
    start = (NOW + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {"_embedded": {"events": [
        {"id": "G5v", "name": "Sabres vs Bruins", "url": "https://tm/1", "dates": {"start": {"dateTime": start}},
         "classifications": [{"segment": {"name": "Sports"}}],
         "_embedded": {"venues": [{"name": "KeyBank Center", "location": {"latitude": "42.875", "longitude": "-78.8764"}}]}},
        {"id": "G6x", "name": "Show elsewhere", "dates": {"start": {"localDate": "2026-11-01"}},
         "_embedded": {"venues": [{"name": "Far venue", "location": {"latitude": "43.1", "longitude": "-79.0"}}]}},
    ]}, "page": {"totalPages": 1}}
    monkeypatch.setattr(events.requests, "get", lambda url, **kw: FakeResp(body))
    assert events.EventsCollector(cfg("events")).collect(ctx) == []
    stored = ctx.store.events_between(NOW, NOW + timedelta(days=30))
    assert [e["facility_id"] for e in stored] == ["keybank_center"]
    assert ctx.store.event_near("keybank_center", NOW + timedelta(days=2, hours=2)) is not None


# ---------------------------------------------------------------- YouTube
def test_youtube(monkeypatch, ctx, matcher):
    from threatwatch.collectors import youtube
    monkeypatch.setenv("YOUTUBE_API_KEY", "k")
    calls = []

    def fake_get(url, params=None, **kw):
        calls.append(params)
        items = [{"id": {"kind": "youtube#video", "videoId": f"v{len(calls)}"},
                  "snippet": {"publishedAt": (NOW - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                              "title": "Fight breaks out at Canalside", "description": "crowd &amp; police",
                              "channelTitle": "Local", "liveBroadcastContent": "live" if len(calls) == 1 else "none"}}]
        return FakeResp({"items": items})

    monkeypatch.setattr(youtube.requests, "get", fake_get)
    posts = youtube.YouTubeCollector(cfg("youtube")).collect(ctx)
    assert len(calls) == len(youtube.DEFAULT_AREAS) + len(cfg("youtube")["queries"])
    assert "locationRadius" in calls[0] and calls[0]["type"] == "video"
    assert posts[0].text.startswith("[LIVE]") and "&amp;" not in posts[0].text
    assert "canalside" in matcher.match(posts[0]).facilities


# ---------------------------------------------------------------- ADS-B
def test_adsb(monkeypatch, ctx, matcher):
    from threatwatch.collectors import adsb
    ac = [{"hex": "a1b2c3", "flight": "N912HP  ", "r": "N912HP", "t": "EC35", "alt_baro": 1100, "gs": 20,
           "lat": 42.7750, "lon": -78.7875, "category": "A7"},                 # low helicopter over Highmark
          {"hex": "aaaaaa", "flight": "DAL12", "alt_baro": 9000, "lat": 42.88, "lon": -78.87},   # high -> ignore
          {"hex": "bbbbbb", "flight": "JBU1", "alt_baro": 1200, "lat": 42.94, "lon": -78.74},    # BUF approach
          {"hex": "cccccc", "alt_baro": "ground", "lat": 42.88, "lon": -78.87}]
    urls = []

    def fake_get(url, **kw):
        urls.append(url)
        if "adsb.lol" in url:
            return FakeResp({}, 503)          # first feed down -> falls back to airplanes.live
        return FakeResp({"ac": ac, "now": 0, "total": len(ac)})

    monkeypatch.setattr(adsb.requests, "get", fake_get)
    posts = adsb.ADSBCollector(cfg("adsb")).collect(ctx)
    assert len(urls) == 2 and "/v2/point/" in urls[1]
    assert len(posts) == 1 and "helicopter" in posts[0].text
    assert matcher.match(posts[0]).facilities == ["highmark_stadium"]
    assert len(ctx.store.tracks_since("aircraft", NOW - timedelta(minutes=5))) == 4


# ---------------------------------------------------------------- AIS
def test_ais(monkeypatch, ctx, matcher):
    import websockets.sync.client as wsc
    from threatwatch.collectors import ais
    monkeypatch.setenv("AISSTREAM_API_KEY", "k")

    def pr(mmsi, name, lat, lon, sog, status=0):
        return json.dumps({"MessageType": "PositionReport",
                           "MetaData": {"MMSI": mmsi, "ShipName": name + "   ", "latitude": lat, "longitude": lon,
                                        "time_utc": "2026-10-20 18:00:00 +0000 UTC"},
                           "Message": {"PositionReport": {"Sog": sog, "Cog": 10, "TrueHeading": 10,
                                                          "NavigationalStatus": status, "Latitude": lat, "Longitude": lon}}})

    msgs = [pr(367001003, "RIVER DAWN", 42.9327, -78.9065, 0.1), pr(367001004, "FAST LANE", 42.865, -78.876, 27.0),
            pr(367001005, "AGROUND ONE", 42.90, -78.903, 0.0, status=6), pr(367001006, "NORMAL", 42.875, -78.885, 5.0)]
    sent = []

    class FakeWS:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def send(self, m): sent.append(json.loads(m))
        def recv(self, timeout=None):
            if msgs:
                return msgs.pop(0)
            raise TimeoutError

    monkeypatch.setattr(wsc, "connect", lambda *a, **k: FakeWS())
    posts = ais.AISCollector({**cfg("ais"), "listen_seconds": 2}).collect(ctx)
    assert sent[0]["BoundingBoxes"][0][0][0] < 50          # [lat, lon] order
    texts = " ".join(p.text for p in posts)
    assert len(posts) == 3 and "stationary vessel" in texts and "high-speed vessel" in texts and "aground" in texts
    assert all(matcher.match(p).is_hit for p in posts)
    assert len(ctx.store.tracks_since("vessel", NOW - timedelta(minutes=5))) == 4


# ---------------------------------------------------------------- Telegram
def test_telegram(monkeypatch, ctx, matcher):
    from threatwatch.collectors import telegram
    msgs = [SimpleNamespace(id=11, message="Shots fired near Canalside, police responding", date=NOW - timedelta(hours=1), views=900),
            SimpleNamespace(id=10, message="", date=NOW - timedelta(hours=2), views=1),
            SimpleNamespace(id=9, message="old", date=NOW - timedelta(days=3), views=1)]

    class FakeClient:
        def connect(self): pass
        def disconnect(self): pass
        def is_user_authorized(self): return True
        def get_entity(self, name): return SimpleNamespace(title="Buffalo Scanner News")
        def iter_messages(self, entity, limit): return iter(msgs)

    monkeypatch.setattr(telegram, "make_client", lambda: FakeClient())
    c = telegram.TelegramCollector({"channels": [{"username": "bufscanner", "reliability": "C", "local": True}]})
    posts = c.collect(ctx)
    assert len(posts) == 1 and posts[0].url == "https://t.me/bufscanner/11" and posts[0].reliability == "C"
    assert "canalside" in matcher.match(posts[0]).facilities
    with pytest.raises(NotConfigured):
        telegram.TelegramCollector({"channels": []}).collect(ctx)


# ---------------------------------------------------------------- full pipeline with not-configured sources
def test_scan_reports_setup_gaps(monkeypatch, tmp_path):
    from threatwatch import pipeline
    for k in ["NY511_API_KEY", "TICKETMASTER_API_KEY", "YOUTUBE_API_KEY", "AISSTREAM_API_KEY",
              "TELEGRAM_API_ID", "BLUESKY_HANDLE"]:
        monkeypatch.delenv(k, raising=False)
    src = load_sources()
    for k, v in src["sources"].items():
        v["enabled"] = k in ("ny511", "events", "youtube", "ais", "telegram")
    monkeypatch.setattr(pipeline, "load_sources", lambda: src)
    r = pipeline.run_scan(send_alerts=False, store=Store(tmp_path / "s.db"))
    assert set(r.not_configured) == {"ny511", "events", "youtube", "ais", "telegram"} and not r.errors
