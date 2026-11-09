"""Tests for the November 2026 upgrade: per-source timing and warnings, light hourly scans, GDELT event
files, keyless Bluesky, new feeds and the Mac notification channel. No network."""
import io
import time
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
import requests

from threatwatch.collectors import CollectContext
from threatwatch.collectors import gdelt
from threatwatch.collectors.bluesky import PDS, PUBLIC, BlueskyCollector
from threatwatch.config import load_facilities, load_keywords, load_sources
from threatwatch.pipeline import ScanResult, collect_all, light_enabled, light_sources_cfg
from threatwatch.store import Store

NOW = datetime.now(timezone.utc)


class FakeResp:
    def __init__(self, data=None, status=200, text="", content=b""):
        self._data, self.status_code, self.text, self.content = data, status, text, content

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


@pytest.fixture
def ctx(tmp_path):
    return CollectContext(load_facilities(), load_keywords(), load_sources(), Store(tmp_path / "u.db"),
                          NOW - timedelta(hours=24))


# ---------------------------------------------------------------- pipeline: timing and warnings
class Sleeper:
    def __init__(self, name, secs, warnings=None):
        self.name, self.secs, self.warnings = name, secs, warnings or []

    def collect(self, ctx):
        time.sleep(self.secs)
        return []


def test_each_source_reports_its_own_time(ctx):
    """Before the fix every source reported the slowest source's time."""
    result = ScanResult()
    collect_all([Sleeper("fast", 0.0), Sleeper("slow", 0.4)], ctx, ctx.store, result, budget_s=10)
    assert result.source_detail["slow"]["seconds"] >= 0.3
    assert result.source_detail["fast"]["seconds"] < 0.2


def test_partial_failure_is_a_warning_not_an_error(ctx):
    result = ScanResult()
    collect_all([Sleeper("news", 0, warnings=["feed failed: WGRZ (timeout)"])], ctx, ctx.store, result)
    assert result.warnings["news"].startswith("feed failed: WGRZ")
    assert "news" not in result.errors
    assert result.source_detail["news"]["error"].startswith("feed failed")


# ---------------------------------------------------------------- light hourly scans
def test_light_scan_keeps_only_fast_sources_and_local_feeds():
    src = load_sources()
    assert light_enabled(src)
    light = light_sources_cfg(src)
    on = {n for n, c in light["sources"].items() if c.get("enabled")}
    assert on <= set(src["scan"]["light"]["sources"])
    assert "opendata" not in on and "news" in on
    news = light["sources"]["news"]
    assert not news["google_news"] and not news["bing_news"] and not news["threat_sweeps"]
    assert news["feeds"]                                 # outlet feeds still run
    assert src["sources"]["news"]["google_news"]         # the original config is untouched


def test_new_local_feeds_are_configured():
    names = {f["name"] for f in load_sources()["sources"]["news"]["feeds"]}
    assert {"The Buffalo News (local)", "WBFO (NPR Buffalo)"} <= names


# ---------------------------------------------------------------- GDELT event files
def row(root="18", adm1="USNY", lat="42.89", lon="-78.87", url="https://www.wkbw.com/news/local-news/man-charged-after-stabbing-at-canalside",
        place="Buffalo, New York, United States", added="20261109201500", a1="POLICE", a2=""):
    r = [""] * 61
    r[gdelt.C_ACTOR1], r[gdelt.C_ACTOR2], r[gdelt.C_ROOT] = a1, a2, root
    r[gdelt.C_GEO_NAME], r[gdelt.C_GEO_ADM1], r[gdelt.C_LAT], r[gdelt.C_LON] = place, adm1, lat, lon
    r[gdelt.C_ADDED], r[gdelt.C_URL] = added, url
    return "\t".join(r)


def zipped(lines):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("x.export.CSV", "\n".join(lines))
    return buf.getvalue()


def test_headline_from_url():
    assert gdelt.headline_from_url("https://www.wgrz.com/article/news/crime/buffalo-man-charged-elmwood-shooting/71-8a7b6c5d-1234") \
        == "Buffalo man charged elmwood shooting"
    assert gdelt.headline_from_url("https://example.com/") == ""


def test_file_stamps_are_quarter_hours():
    s = gdelt.file_stamps(datetime(2026, 11, 9, 19, 7, tzinfo=timezone.utc), datetime(2026, 11, 9, 20, 0, tzinfo=timezone.utc))
    assert s == ["20261109191500", "20261109193000", "20261109194500", "20261109200000"]


def test_gdelt_events_keeps_nearby_threat_events_once_per_article(monkeypatch, ctx):
    latest = "20261109201500"
    lines = [row(), row(root="14"),                                  # same article, two event types
             row(root="04", url="https://x.com/a/meeting-with-mayor-today"),     # not a threat code
             row(adm1="USCA", url="https://x.com/b/stabbing-in-los-angeles"),     # wrong state
             row(lat="40.71", lon="-74.00", url="https://x.com/c/stabbing-in-new-york-city")]   # NYC: too far

    def fake_get(url, **kw):
        if url.endswith("lastupdate.txt"):
            return FakeResp(text=f"1 a http://data.gdeltproject.org/gdeltv2/{latest}.export.CSV.zip\n")
        return FakeResp(content=zipped(lines))

    monkeypatch.setattr(requests, "get", fake_get)
    c = gdelt.GDELTCollector({"mode": "events", "max_files": 1, "root_codes": ["13", "14", "18"]})
    posts = c.collect(ctx)
    assert len(posts) == 1
    p = posts[0]
    assert p.source == "gdelt" and p.source_name == "wkbw.com" and p.reliability == "B"
    assert p.text.startswith("Man charged after stabbing at canalside.")
    assert "assault / protest" in p.text and "Buffalo, New York" in p.text
    assert ctx.store.get_state("gdelt_last_file") == latest
    assert c.collect(ctx) == []          # the same file is not read twice


def test_gdelt_doc_mode_still_available(monkeypatch, ctx):
    called = []
    monkeypatch.setattr(gdelt.GDELTCollector, "collect_doc", lambda self, ctx: called.append(1) or [])
    gdelt.GDELTCollector({"mode": "doc"}).collect(ctx)
    assert called


# ---------------------------------------------------------------- Bluesky without a key
def test_bluesky_without_credentials_uses_public_search(monkeypatch, ctx):
    monkeypatch.delenv("BLUESKY_HANDLE", raising=False)
    monkeypatch.delenv("BLUESKY_APP_PASSWORD", raising=False)
    import threatwatch.collectors.bluesky as bs
    monkeypatch.setattr(bs, "env", lambda k, d=None: None)
    urls = []
    post = {"uri": "at://did:plc:x/app.bsky.feed.post/abc", "author": {"handle": "someone.bsky.social"},
            "record": {"text": "Fight outside KeyBank Center", "createdAt": NOW.isoformat().replace("+00:00", "Z")}}

    def fake_get(self_or_url, *a, **kw):   # requests.Session.get(self, url) or requests.get(url)
        url = a[0] if a else self_or_url
        urls.append(url)
        return FakeResp({"posts": [post]})

    monkeypatch.setattr(requests.Session, "get", fake_get)
    c = BlueskyCollector({"per_query_limit": 5})
    posts = c.collect(ctx)
    assert urls and all(u.startswith(PUBLIC) for u in urls)
    assert c.base == PUBLIC != PDS
    assert len(posts) == 1 and posts[0].url == "https://bsky.app/profile/someone.bsky.social/post/abc"


# ---------------------------------------------------------------- Mac notifications
def test_mac_notifier_builds_a_safe_applescript(monkeypatch):
    import subprocess
    import sys

    from threatwatch import alerts
    monkeypatch.setattr(sys, "platform", "darwin")
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: ran.append(args))
    alerts.MacNotifier().send('Alert: "KeyBank"', [{"score": 72, "facility": 'KeyBank "Center"', "categories": "bomb threat"},
                                                   {"score": 50, "facility": "x", "categories": "y"}])
    script = ran[0][2]
    assert ran[0][:2] == ["osascript", "-e"]
    assert '\\"Center\\"' in script and "(+1 more)" in script and 'with title "ThreatWatch"' in script
    assert "mac" in alerts.NOTIFIERS


# ---------------------------------------------------------------- timestamps from APIs
def test_parse_iso_handles_nanoseconds_and_z():
    from threatwatch.models import parse_iso
    a = parse_iso("2026-11-09T01:02:57.899061308+00:00")          # Bluesky: 9 fractional digits
    assert (a.microsecond, a.tzinfo) == (899061, timezone.utc)
    assert parse_iso("2026-11-09T01:02:57Z") == datetime(2026, 11, 9, 1, 2, 57, tzinfo=timezone.utc)
    assert parse_iso("2026-11-09T01:02:57.5-05:00").hour == 6    # converted to UTC
    assert parse_iso("2026-11-09T01:02:57").tzinfo == timezone.utc
