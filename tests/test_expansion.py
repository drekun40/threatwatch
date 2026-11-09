"""Wider collection: Bing/Google news plan + dedupe, GDELT, FAA TFR, Mastodon, parallel scans."""
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from threatwatch.collectors import CollectContext, NotConfigured
from threatwatch.config import load_facilities, load_keywords, load_sources
from threatwatch.matcher import Matcher
from threatwatch.store import Store

NOW = datetime.now(timezone.utc)


class FakeResp:
    def __init__(self, data=None, text=None, content=b"", status=200):
        self._data, self.status_code, self.content = data, status, content
        self.text = text if text is not None else json.dumps(data)

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.fixture
def ctx(tmp_path):
    return CollectContext(load_facilities(), load_keywords(), load_sources(), Store(tmp_path / "c.db"),
                          NOW - timedelta(hours=24))


def rfc822(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def test_bing_link_decoded_and_titles_deduped(ctx, monkeypatch):
    from threatwatch.collectors import news
    pub = rfc822(NOW - timedelta(hours=1))
    google = f"""<rss><channel><item><title>Shooting near Canalside - WGRZ</title>
      <link>https://news.google.com/rss/articles/abc</link><pubDate>{pub}</pubDate>
      <source url="https://www.wgrz.com">WGRZ</source></item></channel></rss>""".encode()
    bing = f"""<rss xmlns:News="x"><channel><item><title>Shooting near Canalside</title>
      <link>https://www.bing.com/news/apiclick.aspx?ref=FexRss&amp;url=https%3a%2f%2fwww.wkbw.com%2fnews%2fa1&amp;c=1</link>
      <pubDate>{pub}</pubDate><News:Source>WKBW</News:Source></item>
      <item><title>Bomb threat at City Hall</title>
      <link>https://www.bing.com/news/apiclick.aspx?url=https%3a%2f%2fwww.wivb.com%2fnews%2fb2&amp;c=1</link>
      <pubDate>{pub}</pubDate><News:Source>WIVB</News:Source></item></channel></rss>""".encode()

    def fake_get(url, **kw):
        if "news.google.com" in url:
            return FakeResp(content=google, text="")
        if "bing.com" in url:
            return FakeResp(content=bing, text="")
        return FakeResp(content=b"<rss><channel></channel></rss>", text="")
    monkeypatch.setattr(news.requests, "get", fake_get)
    c = news.NewsCollector(load_sources()["sources"]["news"])
    plan = c.plan(ctx)
    assert any("bing.com" in r["url"] for r in plan) and any("news.google.com" in r["url"] for r in plan)
    assert sum(1 for r in plan if r["engine"] == "google") > 27          # per-site + threat sweeps
    posts = c.collect(ctx)
    texts = [p.text for p in posts]
    assert sum("Canalside" in t for t in texts) == 1                      # same story kept once
    bomb = next(p for p in posts if "Bomb threat" in p.text)
    assert bomb.url == "https://www.wivb.com/news/b2" and bomb.reliability == "B"


def test_gdelt(ctx, monkeypatch):
    from threatwatch.collectors import gdelt
    seen = NOW.strftime("%Y%m%dT%H%M%SZ")
    calls = []

    def fake_get(url, params=None, **kw):
        calls.append(params["query"])
        if len(calls) == 2:
            return FakeResp(text="Your search contained a phrase that was too short.")
        return FakeResp({"articles": [{"url": "https://example.com/a", "title": "Lockdown at Buffalo City Hall",
                                       "seendate": seen, "domain": "example.com"}]})
    monkeypatch.setattr(gdelt.requests, "get", fake_get)
    monkeypatch.setattr(gdelt.time, "sleep", lambda s: None)
    posts = gdelt.GDELTCollector({"enabled": True, "mode": "doc"}).collect(ctx)
    assert len(posts) == 1 and posts[0].source == "gdelt" and posts[0].reliability == "C"
    assert all("sourcelang:english" in q for q in calls) and len(calls) >= 4
    hit = Matcher(load_facilities(), load_keywords()).match(posts[0])
    assert hit.is_hit and "city_hall" in hit.facilities


def test_tfr_keeps_buffalo_only(ctx, monkeypatch):
    from threatwatch.collectors import tfr
    data = [{"notam_id": "6/0096", "type": "SECURITY", "state": "NY", "creation_date": "10/18/2026",
             "description": "NEW YORK, NY, Tuesday, October 20, 2026"},
            {"notam_id": "6/1234", "type": "VIP", "state": "NY", "creation_date": NOW.strftime("%m/%d/%Y"),
             "description": "BUFFALO, NY, Friday, October 23, 2026 Local"},
            {"notam_id": "6/5555", "type": "HAZARDS", "state": "TX", "creation_date": "10/18/2026",
             "description": "BUFFALO, TX"}]
    monkeypatch.setattr(tfr.requests, "get", lambda *a, **k: FakeResp(data))
    posts = tfr.TFRCollector({}).collect(ctx)
    assert [p.native_id for p in posts] == ["6/1234"]
    assert posts[0].reliability == "A" and "detail_6_1234" in posts[0].url
    assert Matcher(load_facilities(), load_keywords()).match(posts[0]).is_hit


def test_mastodon(ctx, monkeypatch):
    from threatwatch.collectors import mastodon
    status = lambda i, lang, hours: {"id": str(i), "uri": f"https://m/{i}", "url": f"https://m/@a/{i}",
                                     "created_at": (NOW - timedelta(hours=hours)).isoformat().replace("+00:00", "Z"),
                                     "language": lang, "content": f"<p>Police lockdown at KeyBank Center {i}</p>",
                                     "account": {"acct": "a"}, "favourites_count": 1}
    monkeypatch.setattr(mastodon.requests, "get",
                        lambda url, **k: FakeResp([status(1, "en", 1), status(2, "fr", 1), status(3, "en", 30)]))
    posts = mastodon.MastodonCollector({"tags": ["buffalo"], "pages": 2}).collect(ctx)
    assert [p.native_id for p in posts] == ["https://m/1"]
    assert posts[0].text.startswith("Police lockdown") and posts[0].reliability == "D"


def test_parallel_collect_with_timeout(tmp_path):
    from threatwatch.models import Post
    from threatwatch.pipeline import ScanResult, collect_all

    class C:
        def __init__(self, name, delay=0.0, fail=None):
            self.name, self.delay, self.fail = name, delay, fail

        def collect(self, ctx):
            time.sleep(self.delay)
            if self.fail:
                raise self.fail
            ctx.store.set_state(f"ran_{self.name}", True)       # writes go through the locked store
            return [Post(self.name, self.name, "1", "", "x", NOW)]

    store = Store(tmp_path / "p.db")
    ctx = CollectContext({}, {}, {}, store, NOW - timedelta(hours=1))
    res = ScanResult()
    t0 = time.monotonic()
    posts = collect_all([C("a", 0.3), C("b", 0.3), C("c", 0.3), C("slow", 5), C("bad", fail=ValueError("boom")),
                         C("cfg", fail=NotConfigured("no key"))], ctx, store, res, budget_s=1.5)
    assert time.monotonic() - t0 < 3                          # ran in parallel, didn't wait for "slow"
    assert sorted(p.source for p in posts) == ["a", "b", "c"]
    h = store.source_health()
    assert h["slow"]["state"] == "error" and "still running" in h["slow"]["last_error"]
    assert h["bad"]["state"] == "error" and h["cfg"]["state"] == "not_configured" and h["a"]["state"] == "ok"
    assert store.get_state("ran_a") is True


def test_auto_cadence(tmp_path):
    from zoneinfo import ZoneInfo

    from threatwatch.pipeline import auto_reason
    store = Store(tmp_path / "a.db")
    cfg = load_sources()
    et = ZoneInfo("America/New_York")
    at = lambda h: datetime(2026, 10, 21, h, 0, tzinfo=et).astimezone(timezone.utc)
    assert "07:00" in auto_reason(store, cfg, at(7))
    assert auto_reason(store, cfg, at(11)) is None
    store.upsert_event({"id": "e1", "source": "NHL", "name": "Sabres vs Flyers", "venue": "KeyBank Center",
                        "facility_id": "keybank_center", "start_at": at(19).isoformat(), "url": "",
                        "lat": None, "lon": None, "info": {}})
    store.commit()
    assert auto_reason(store, cfg, at(11)) is None          # 8 h before: not yet
    assert "Sabres" in auto_reason(store, cfg, at(14) + timedelta(minutes=1))
    assert "Sabres" in auto_reason(store, cfg, at(21))      # 2 h after start


REAL = [   # headlines from the first wide scan on 2026-10-20, with the tier they should get
    ("WKBW (all news)", True, "Minnesota teen accused of plotting terror attack at Mall of America to remain jailed. "
     "An 18-year-old from Minnesota who prosecutors say planned a terror attack", None),
    ("WKBW (all news)", True, "Mississippi AG says officer's force was justified during shoplifting call in which "
     "boy was killed. Mississippi's attorney general says a Senatobia officer was justified in a shooting", None),
    ("North Country Now", False, "Owner identified in water buffalo crash in Stockholm - North Country Now", None),
    ("Buffalo News", False, "Ready to blow up baseball for a salary cap, MLB can't spin this World Series - Buffalo News", None),
    ("Spectrum News", False, "Chippewa Street bars suing city of Buffalo over age restrictions, closures. The city set "
     "the restriction after a string of violent incidents and disturbances", "WATCH"),
    ("WIVB News 4", False, "Man shot several times in Buffalo. Buffalo Police responded to a shots-fired call on "
     "Schreck Avenue", "WATCH"),
]


@pytest.mark.parametrize("outlet,local,text,want", REAL)
def test_precision_on_real_headlines(outlet, local, text, want):
    from threatwatch.models import Post
    from threatwatch.scoring import score_match
    m = Matcher(load_facilities(), load_keywords())
    post = Post("news", outlet, text[:20], "", text, NOW, reliability="B", is_local=local)
    match = m.match(post)
    if want is None:
        assert not match.is_hit, match
        return
    tiers = [score_match(post, match, fid, m, 0, load_sources()["tiers"]).tier for fid in match.facilities]
    assert "ALERT" not in tiers and want in tiers, (tiers, match)


def test_rescore_closes_and_caps(tmp_path):
    from threatwatch.models import Hit, Post
    from threatwatch.pipeline import rescore
    store = Store(tmp_path / "r.db")
    p1 = Post("news", "WKBW (all news)", "a", "", "Minnesota teen plotting terror attack at Mall of America", NOW,
              reliability="B", is_local=True)
    p2 = Post("news", "WIVB", "b", "", "Bomb threat and active shooter in Buffalo, police say", NOW, reliability="B")
    for p in (p1, p2):
        store.add_post(p)
        store.add_hit(Hit(p, "area_general", ["explosives_terrorism"], ["terror attack"], 90, "ALERT", "B4"))
    store.commit()
    r = rescore(store)
    assert r == {"checked": 2, "changed": 1, "closed": 1}
    tiers = {row["post_uid"]: (row["tier"], row["status"]) for row in store.conn.execute("SELECT * FROM hits")}
    assert tiers[p1.uid][1] == "closed" and tiers[p2.uid] == ("WATCH", "new")


def test_http_retry(monkeypatch):
    import requests

    from threatwatch import http
    monkeypatch.setattr(http.time, "sleep", lambda s: None)
    seq = [requests.ConnectionError("reset"), FakeResp({}, status=503), FakeResp({"ok": 1})]
    calls = []

    def fake(url, **kw):
        calls.append(kw.get("timeout"))
        x = seq.pop(0)
        if isinstance(x, Exception):
            raise x
        return x
    monkeypatch.setattr(requests, "get", fake)
    assert http.get("https://x").json() == {"ok": 1} and calls == [20, 20, 20]
    monkeypatch.setattr(requests, "get", lambda url, **kw: FakeResp({}, status=429))
    assert http.get("https://x").status_code == 429            # rate limits are not retried
    n = []
    monkeypatch.setattr(requests, "get", lambda url, **kw: n.append(1) or FakeResp({}, status=502))
    assert http.get("https://x").status_code == 502 and len(n) == 3   # gives up after 3, caller raises

    def down(url, **kw):
        raise requests.Timeout("slow")
    monkeypatch.setattr(requests, "get", down)
    with pytest.raises(requests.Timeout):
        http.get("https://x")


# ---------------------------------------------------------------- ACT tier + score_match
@pytest.mark.parametrize("score,fid,w,rel,corr,want", [
    (90, "keybank_center", 10, "B", 0, "ACT"),      # high score, trusted source
    (90, "keybank_center", 10, "D", 1, "ACT"),      # high score, corroborated
    (90, "keybank_center", 10, "D", 0, "ALERT"),    # high score but single unverified source
    (84, "keybank_center", 10, "A", 2, "ALERT"),
    (70, "keybank_center", 9, "C", 0, "ALERT"),
    (69, "keybank_center", 9, "C", 0, "WATCH"),
    (40, "keybank_center", 5, "C", 0, "WATCH"),
    (39, "keybank_center", 5, "C", 0, "LOG"),
    (95, "area_general", 10, "A", 3, "WATCH"),      # no site: never above Watch
    (95, "area_general", 8, "A", 3, "LOG"),         # no site and weight < 9: Logged
])
def test_tier_for(score, fid, w, rel, corr, want):
    from threatwatch.scoring import tier_for
    assert tier_for(score, fid, w, rel, corr, load_sources()["tiers"])[0] == want


def test_score_match_is_explained_and_deterministic():
    from threatwatch.models import Post
    from threatwatch.scoring import score_match
    m = Matcher(load_facilities(), load_keywords())
    post = Post("news", "WGRZ", "x", "https://wgrz.com/a", "Bomb threat at KeyBank Center during Sabres game",
                NOW - timedelta(hours=1), reliability="B")
    match = m.match(post)
    tiers = load_sources()["tiers"]
    a = score_match(post, match, "keybank_center", m, 1, tiers, event_day=True)
    b = score_match(post, match, "keybank_center", m, 1, tiers, event_day=True)
    assert (a.score, a.tier, a.admiralty) == (b.score, b.tier, b.admiralty)
    assert a.score == min(100, sum(p for _, p in a.factors))          # breakdown adds up
    assert a.tier == "ACT" and a.admiralty == "B3"


def test_act_is_dispatched_first(tmp_path, monkeypatch):
    from threatwatch import alerts
    from threatwatch.models import Hit, Post
    store = Store(tmp_path / "d.db")
    for i, tier in enumerate(["ALERT", "ACT", "WATCH"]):
        p = Post("news", "WGRZ", str(i), "", f"item {i}", NOW, reliability="B")
        store.add_post(p)
        store.add_hit(Hit(p, "keybank_center", ["explosives_terrorism"], ["bomb threat"], 80 - i, tier, "B4"))
    store.commit()
    rows = store.pending_alerts()
    assert [r["tier"] for r in rows] == ["ACT", "ALERT"]
    sent = []
    monkeypatch.setattr(alerts, "send", lambda subject, items: (sent.append(subject), (1, []))[1])
    assert alerts.dispatch_alerts(store, Matcher(load_facilities(), load_keywords())) == 2
    assert "ACT NOW (1)" in sent[0] and not store.pending_alerts()


# ---------------------------------------------------------------- scan summary email
def _result(hits):
    from threatwatch.pipeline import ScanResult
    return ScanResult(collected=120, new_posts=30, hits=hits, alerts_sent=1, errors={"gdelt": "429"},
                      not_configured={"youtube": "no key"}, per_source={"news": 100, "nws": 2})


def test_summary_email_content():
    from threatwatch.alerts import build_scan_summary
    from threatwatch.models import Hit, Post
    m = Matcher(load_facilities(), load_keywords())
    hits = [Hit(Post("news", "WGRZ", str(i), f"https://x/{i}", f"text {i}", NOW), "canalside", [], [], s, t, "B3")
            for i, (s, t) in enumerate([(90, "ACT"), (72, "ALERT"), (50, "WATCH"), (20, "LOG")])]
    subject, text, html = build_scan_summary(_result(hits), m)
    assert subject == "ThreatWatch scan — 30 new, 2 alerts, 1 watch (1 ACT NOW)"
    assert "gdelt: 429" in text and "youtube" in text and "https://x/0" in text and "text 3" not in text
    assert text.index("text 0") < text.index("text 1") < text.index("text 2")
    assert "Act now" in html and "https://x/1" in html
    s0, t0, _ = build_scan_summary(_result([]), m)              # zero hits still produces a summary
    assert s0.startswith("ThreatWatch scan — 30 new, 0 alerts, 0 watches") and "No Alert or Watch items" in t0


def test_summary_email_gating(monkeypatch):
    from threatwatch import alerts
    env = {"ALERT_CHANNELS": "console"}
    monkeypatch.setattr(alerts, "env", lambda k, d=None: env.get(k, d))
    m = Matcher(load_facilities(), load_keywords())
    assert alerts.send_scan_summary(_result([]), m) == (False, "summary email skipped: email is not in ALERT_CHANNELS")
    env.update({"ALERT_CHANNELS": "teams,email", "SMTP_HOST": "smtp.x", "ALERT_EMAIL_TO": "a@b.c"})
    sent = []
    monkeypatch.setattr(alerts.EmailNotifier, "send_text", lambda self, s, t, h=None, a=None: sent.append(s))
    ok, msg = alerts.send_scan_summary(_result([]), m)
    assert ok and sent and "a@b.c" in msg
    env["SCAN_SUMMARY_EMAIL"] = "0"
    assert alerts.send_scan_summary(_result([]), m)[0] is False

    def boom(self, *a):
        raise OSError("smtp down")
    env["SCAN_SUMMARY_EMAIL"] = "1"
    monkeypatch.setattr(alerts.EmailNotifier, "send_text", boom)
    ok, msg = alerts.send_scan_summary(_result([]), m)
    assert not ok and "failed: smtp down" in msg


def test_run_scan_reports_delivery(tmp_path, monkeypatch):
    from threatwatch import alerts, pipeline
    from threatwatch.models import Post

    class Fake:
        name = "news"

        def collect(self, ctx):
            return [Post("news", "WGRZ", "1", "https://wgrz.com/1", "Bomb threat at KeyBank Center, police say",
                         NOW - timedelta(minutes=30), reliability="B")]
    monkeypatch.setattr(pipeline, "get_collectors", lambda cfg: [Fake()])
    monkeypatch.setattr(pipeline, "write_excel", lambda *a, **k: str(tmp_path / "x.xlsx"))
    env = {"ALERT_CHANNELS": "email", "SMTP_HOST": "smtp.x", "ALERT_EMAIL_TO": "a@b.c"}
    monkeypatch.setattr(alerts, "env", lambda k, d=None: env.get(k, d))
    sent = []
    monkeypatch.setattr(alerts.EmailNotifier, "send_text", lambda self, s, t, h=None, a=None: sent.append(("summary", s)))
    monkeypatch.setattr(alerts.EmailNotifier, "send", lambda self, s, items: sent.append(("alert", s)))
    r = pipeline.run_scan(store=Store(tmp_path / "s.db"))
    assert r.tier_counts()["ACT"] + r.tier_counts()["ALERT"] == 1
    assert [k for k, _ in sent] == ["alert", "summary"]
    assert r.delivery["alerts"]["ok"] and r.delivery["alerts"]["sent"] == 1
    assert r.delivery["summary"] == {"ok": True, "sent": True, "message": "summary email sent to a@b.c"}
    r2 = pipeline.run_scan(store=Store(tmp_path / "s.db"))       # nothing new: summary still goes out
    assert r2.new_posts == 0 and sent[-1][0] == "summary" and "0 new" in sent[-1][1]


def test_online_check(monkeypatch):
    import socket

    from threatwatch import pipeline
    calls = []

    def fake(host, port):
        calls.append(host)
        if len(calls) < 3:
            raise socket.gaierror("no dns")
        return [("ok",)]
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert pipeline.online(tries=3, wait_s=0) is True and len(calls) == 3
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p: (_ for _ in ()).throw(socket.gaierror("x")))
    assert pipeline.online(tries=2, wait_s=0) is False


def test_dashboard_settings_override_and_env(tmp_path, monkeypatch):
    import os

    from threatwatch import config
    monkeypatch.setattr(config, "SOURCES_LOCAL_FILE", tmp_path / "sources.local.yaml")
    monkeypatch.setattr(config, "ENV_FILE", tmp_path / ".env")
    (tmp_path / ".env").write_text("# keys\nYOUTUBE_API_KEY=\nALERT_CHANNELS=console\n")
    config.save_source_settings("telegram", {"enabled": True, "channels": [{"username": "a"}]})
    config.save_source_settings("telegram", {"per_channel_limit": 50})
    s = config.load_sources()["sources"]["telegram"]
    assert s["enabled"] and s["channels"] == [{"username": "a"}] and s["per_channel_limit"] == 50
    assert config.load_sources()["sources"]["news"]["feeds"]                  # base file still applies
    config.set_env({"YOUTUBE_API_KEY": "k1", "NEW_KEY": "v"})
    txt = (tmp_path / ".env").read_text()
    assert "# keys" in txt and "YOUTUBE_API_KEY=k1" in txt and "ALERT_CHANNELS=console" in txt and "NEW_KEY=v" in txt
    assert os.environ["YOUTUBE_API_KEY"] == "k1"
    monkeypatch.delenv("YOUTUBE_API_KEY"); monkeypatch.delenv("NEW_KEY")


def test_check_source_reports_setup_gap(monkeypatch):
    from threatwatch import setup
    monkeypatch.delenv("YOUTUBE_API_KEY", raising=False)
    r = setup.check_source("youtube")
    assert r["ok"] is False and r["message"].startswith("Not set up")
    assert not setup.is_connected("youtube")


def test_collection_log_template(tmp_path, monkeypatch):
    import csv
    import io

    from openpyxl import load_workbook

    from threatwatch import alerts, export, pipeline
    from threatwatch.collection import headers
    from threatwatch.models import Post

    class Fake:
        name = "news"

        def collect(self, ctx):
            return [Post("news", "WGRZ", "1", "https://wgrz.com/1", "Bomb threat at KeyBank Center, police say",
                         NOW - timedelta(minutes=30), reliability="B", engagement={"via": "Google News RSS"}),
                    Post("news", "Buffalo Rising", "2", "https://br.com/2", "New bakery opens on Elmwood",
                         NOW - timedelta(hours=2), reliability="C")]

    class Down:
        name = "gdelt"

        def collect(self, ctx):
            raise RuntimeError("429")
    monkeypatch.setattr(pipeline, "get_collectors", lambda cfg: [Fake(), Down()])
    monkeypatch.setattr(pipeline, "write_excel", lambda *a, **k: str(tmp_path / "x.xlsx"))
    monkeypatch.setattr(export, "COLLECTION_XLSX", tmp_path / "log.xlsx")
    monkeypatch.setattr(alerts, "env", lambda k, d=None: {"ALERT_CHANNELS": "console"}.get(k, d))
    store = Store(tmp_path / "c.db")
    r = pipeline.run_scan(store=store)
    rows = store.collection(scan_id=r.scan_id)
    assert len(rows) == 2
    bomb = next(x for x in rows if "Bomb" in x["title"])
    assert bomb["phase"] == "Facility-Specific" and bomb["threat_level"] == "High"
    assert bomb["tool"] == "ThreatWatch › Google News RSS" and bomb["analyst_notes"].startswith("Auto:")
    bakery = next(x for x in rows if "bakery" in x["title"])
    assert bakery["phase"] == "General/Industry" and bakery["threat_level"] == "Low"
    srcs = {s["source"]: s for s in store.scan_sources(r.scan_id)}
    assert srcs["news"]["items"] == 2 and srcs["news"]["new"] == 2 and srcs["gdelt"]["state"] == "error"
    r2 = pipeline.run_scan(store=store)                          # repeats are counted, not logged again
    assert store.collection(scan_id=r2.scan_id) == [] and store.scan_sources(r2.scan_id)[0]["items"] >= 2
    wb = load_workbook(tmp_path / "log.xlsx")
    ws = wb["Collection log"]
    hdr = [c.value for c in ws[1]]
    assert hdr[:11] == headers(False) and hdr[0] == "Date Collected" and hdr[10].startswith("Preliminary Threat Level")
    assert ws.max_row == 3 and "Sources per scan" in wb.sheetnames
    vals = {c.value for c in ws[2]} | {c.value for c in ws[3]}
    assert "Tier 2 – established media" in vals and "B – Usually reliable" in vals
    text = alerts.collection_csv(r).decode("utf-8-sig")
    assert next(csv.reader(io.StringIO(text)))[:11] == headers(False)
    store.update_collection(bomb["id"], analyst_notes="Checked with BPD", threat_level="Moderate")
    assert store.collection(scan_id=r.scan_id)[-1]["analyst_notes"] in ("Checked with BPD", bakery["analyst_notes"])
