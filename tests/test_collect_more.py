"""Collect-more upgrade: nearby-street matching, full article text, catch-up scans. No network."""
from datetime import datetime, timedelta, timezone

import pytest

from threatwatch import article
from threatwatch.config import load_facilities, load_keywords, load_sources
from threatwatch.matcher import AREA_GENERAL, Matcher
from threatwatch.models import Post
from threatwatch.pipeline import auto_reason
from threatwatch.scoring import score_match
from threatwatch.store import Store

NOW = datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def matcher():
    return Matcher(load_facilities(), load_keywords())


def post(text, local=True, source="news", url="https://www.wkbw.com/news/x", body=""):
    return Post(source, "WKBW", url, url, text, NOW - timedelta(minutes=20), reliability="B", is_local=local, body=body)


def a_nearby_intersection(fid):
    fac = next(f for f in load_facilities()["facilities"] if f["id"] == fid)
    return next(t for t in fac["nearby"] if " and " in t)


# ---------------------------------------------------------------- nearby streets
def test_intersection_places_a_story_at_the_nearest_site(matcher):
    corner = a_nearby_intersection("keybank_center")
    m = matcher.match(post(f"Shooting reported near {corner} in Buffalo"))
    assert "keybank_center" in m.facilities and not m.area_only
    assert m.proximity["keybank_center"] == corner


def test_nearby_needs_buffalo_context(matcher):
    corner = a_nearby_intersection("keybank_center")
    m = matcher.match(post(f"Shooting reported near {corner}", local=False))
    assert "keybank_center" not in m.facilities


def test_nearby_is_case_sensitive(matcher):
    m = matcher.match(post("buffalo has the best street food; a stabbing was reported downtown", local=True))
    assert not m.proximity


def test_named_site_wins_over_nearby(matcher):
    corner = a_nearby_intersection("keybank_center")
    m = matcher.match(post(f"Bomb threat at KeyBank Center, near {corner}, Buffalo"))
    assert "keybank_center" in m.facilities and "keybank_center" not in m.proximity


def test_nearby_scores_five_lower_and_says_why(matcher):
    corner = a_nearby_intersection("keybank_center")
    p = post(f"Shooting reported near {corner} in Buffalo")
    m = matcher.match(p)
    hit = score_match(p, m, "keybank_center", matcher, 0, load_sources()["tiers"])
    assert ("Placed by nearby street, not named: " + corner, -5) in hit.factors


def test_body_text_is_matched(matcher):
    corner = a_nearby_intersection("keybank_center")
    p = post("Man arrested downtown", body=f"Police said the stabbing happened near {corner} in Buffalo.")
    m = matcher.match(p)
    assert m.is_hit and "keybank_center" in m.facilities


# ---------------------------------------------------------------- full article text
PAGE = """<html><head><script>var x = "<p>not this</p>";</script></head><body>
<nav><p>Home News Sports Weather and a very long navigation line that should never be read here</p></nav>
<p>By Staff</p>
<p>Buffalo police said a man was stabbed near Perry and Illinois streets on Saturday night after a game.</p>
<p>The victim was taken to Erie County Medical Center in stable condition, according to the department.</p>
<aside><p>Related: an unrelated shooting story in another city that should not leak into the article text</p></aside>
<footer><p>Copyright 2026 and other footer text long enough to pass the length filter easily</p></footer>
</body></html>"""


def test_extract_text_keeps_article_paragraphs_only():
    text = article.extract_text(PAGE)
    assert text.startswith("Buffalo police said a man was stabbed near Perry and Illinois")
    assert "Erie County Medical Center" in text
    assert "navigation" not in text and "unrelated" not in text and "By Staff" not in text and "not this" not in text


def test_candidates_order_and_skips(matcher):
    area = post("Stabbing in Buffalo overnight", url="https://www.wivb.com/a")
    local_quiet = post("New bakery opens on Hertel", url="https://www.wkbw.com/b")
    google = post("Stabbing in Buffalo", url="https://news.google.com/rss/articles/xyz")
    paywalled = post("Stabbing in Buffalo", url="https://buffalonews.com/c")
    social = post("Stabbing in Buffalo", source="bluesky", url="https://bsky.app/d")
    got = article.candidates([local_quiet, google, paywalled, social, area], matcher, ["buffalonews.com"])
    assert got == [area, local_quiet]


def test_enrich_fills_body_and_counts(monkeypatch, matcher):
    monkeypatch.setattr(article, "fetch_body", lambda url, *a, **kw: "Police said it happened near the arena.")
    p, seen = post("Stabbing in Buffalo overnight", url="https://www.wivb.com/a"), post("Old", url="https://www.wivb.com/old")
    out = article.enrich([p, seen], matcher, {"max_per_scan": 5}, is_new=lambda x: x is p)
    assert out == {"fetched": 1, "tried": 1} and p.body.startswith("Police said") and not seen.body


def test_robots_txt_is_honoured(monkeypatch):
    class R:
        status_code, text = 200, "User-agent: *\nDisallow: /private/\n"
    monkeypatch.setattr(article.http, "get", lambda url, **kw: R())
    article._robots.clear()
    assert article.allowed("https://example.org/news/story")
    assert not article.allowed("https://example.org/private/story")


def test_body_survives_storage_and_rescore(tmp_path):
    st = Store(tmp_path / "b.db")
    p = post("Headline", url="https://www.wivb.com/z", body="Full text here")
    assert st.add_post_status(p) == "new" and st.is_stored(p)
    assert st.conn.execute("SELECT body FROM posts WHERE uid=?", (p.uid,)).fetchone()["body"] == "Full text here"


# ---------------------------------------------------------------- catch-up after a gap
def test_catch_up_after_the_computer_slept(tmp_path):
    st = Store(tmp_path / "c.db")
    src = load_sources()
    quiet = datetime(2026, 11, 17, 16, 0, tzinfo=timezone.utc)          # 11:00 ET: not a base hour
    sid = st.begin_scan(quiet - timedelta(hours=5))
    st.log_scan(quiet - timedelta(hours=5), 0, 0, 0, 0, {}, {"kind": "light"}, scan_id=sid)
    st.conn.execute("UPDATE scans SET finished_at=? WHERE id=?", ((quiet - timedelta(hours=5)).isoformat(), sid))
    assert auto_reason(st, src, now=quiet).startswith("catching up: no scan for 5 h")
    st.conn.execute("UPDATE scans SET finished_at=? WHERE id=?", ((quiet - timedelta(minutes=50)).isoformat(), sid))
    assert auto_reason(st, src, now=quiet) is None                      # recent scan: a light hour


# ---------------------------------------------------------------- planned public gatherings
def mob_event(**kw):
    ev = {"id": 77, "title": "Ice Out Now", "event_type": "VISIBILITY_EVENT", "visibility": "PUBLIC", "is_virtual": False,
          "browser_url": "https://www.mobilize.us/x/event/77/",
          "location": {"venue": "", "address_lines": ["250 Delaware Avenue"], "locality": "Buffalo",
                       "location": {"latitude": 42.8875, "longitude": -78.8768}},
          "timeslots": [{"id": 5, "start_date": int((NOW + timedelta(hours=3)).timestamp())}]}
    ev.update(kw)
    return ev


def test_gatherings_store_nearby_public_in_person_events_only(monkeypatch, tmp_path):
    from threatwatch.collectors import CollectContext
    from threatwatch.collectors import gatherings
    events = [mob_event(),
              mob_event(id=78, event_type="PHONE_BANK"),                       # not a crowd
              mob_event(id=79, is_virtual=True),                               # online
              mob_event(id=80, location={"locality": "Buffalo"}),               # private address
              mob_event(id=81, location={"location": {"latitude": 42.95, "longitude": -78.70}})]   # nowhere near a site

    class R:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"data": events}
    monkeypatch.setattr(gatherings.http, "get", lambda url, **kw: R())
    st = Store(tmp_path / "g.db")
    ctx = CollectContext(load_facilities(), load_keywords(), load_sources(), st, NOW - timedelta(hours=24))
    assert gatherings.GatheringsCollector({"zipcodes": ["14202"]}).collect(ctx) == []
    rows = st.conn.execute("SELECT * FROM events").fetchall()
    assert len(rows) == 1 and rows[0]["id"] == "mobilize:77:5" and rows[0]["source"] == "mobilize"
    assert rows[0]["name"] == "Demonstration: Ice Out Now" and rows[0]["facility_id"]
    assert st.get_state("gatherings_last_count") == 1
    from zoneinfo import ZoneInfo
    when = NOW if NOW.astimezone(ZoneInfo("America/New_York")).hour not in (7, 15) else NOW + timedelta(hours=1)
    assert auto_reason(st, load_sources(), now=when).startswith("event window: Demonstration")


def test_court_searches_are_configured():
    qs = load_sources()["sources"]["news"]["extra_queries"]
    assert any("Western District of New York" in q for q in qs)


def test_body_only_evidence_never_alerts(matcher):
    """Regression: a former Bills player's arrest story reached Alert at Highmark Stadium because the
    article text added 'weapons/violence' terms the headline didn't have."""
    p = post("Former Buffalo Bills star arrested in Florida",
             body="Police said he punched an officer and was charged with assault and battery with a weapon.")
    p.reliability = "A"
    m = matcher.match(p)
    assert "highmark_stadium" in m.facilities and m.body_categories
    hit = score_match(p, m, "highmark_stadium", matcher, 2, load_sources()["tiers"])
    assert hit.tier == "WATCH"
    assert any(t.startswith("Capped at Watch:") for t, _ in hit.factors)


def test_headline_evidence_still_alerts(matcher):
    p = post("Bomb threat forces evacuation at KeyBank Center in Buffalo", body="More details in the article.")
    p.reliability = "A"
    m = matcher.match(p)
    hit = score_match(p, m, "keybank_center", matcher, 1, load_sources()["tiers"])
    assert hit.tier in ("ALERT", "ACT") and not m.body_sites and not m.body_categories
