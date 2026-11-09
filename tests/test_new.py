"""Excel log, team schedules, manual events and keyword pack."""
from datetime import datetime, timedelta, timezone

import pytest
from openpyxl import load_workbook

from threatwatch.config import load_facilities, load_keywords, load_sources
from threatwatch.matcher import Matcher
from threatwatch.models import Post
from threatwatch.pipeline import process_posts
from threatwatch.store import Store

NOW = datetime.now(timezone.utc)
TEAM_S = {"key": "sabres", "kind": "nhl", "team": "BUF", "facility_id": "keybank_center", "venue": "KeyBank Center"}
TEAM_B = {"key": "bills", "kind": "espn", "sport": "football", "league": "nfl", "team": "buf",
          "facility_id": "highmark_stadium", "venue": "Highmark Stadium"}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_excel_only_alert_and_watch(tmp_path, monkeypatch):
    from threatwatch import export
    monkeypatch.setattr(export, "XLSX", tmp_path / "log.xlsx")
    store, m = Store(tmp_path / "x.db"), Matcher(load_facilities(), load_keywords())
    posts = [Post("news", "WGRZ (NBC 2)", "a", "https://www.wgrz.com/a", "Bomb threat at Buffalo City Hall",
                  NOW - timedelta(hours=1), reliability="B", is_local=True),
             Post("bluesky", "Bluesky", "b", "https://bsky.app/b", "Graffiti on the Broadway Market wall",
                  NOW - timedelta(hours=2))]
    _, hits = process_posts(posts, store, m, load_sources())
    tiers = {h.tier for h in hits}
    assert "LOG" in tiers and "ALERT" in tiers
    path = export.write_excel(store, m, [1])
    wb = load_workbook(path)
    assert wb.sheetnames == ["Alerts & Watch", "Latest scan", "Upcoming events", "Scan log"]
    ws = wb["Alerts & Watch"]
    levels = [ws.cell(row=r, column=3).value for r in range(2, ws.max_row + 1)]
    assert levels and set(levels) <= {"Alert", "Watch"}
    link = ws.cell(row=2, column=13)
    assert link.value == "Open source" and link.hyperlink.target.startswith("https://")
    # same header every time
    assert [c.value for c in ws[1]] == [h for h, _ in export.COLUMNS]


def test_parse_nhl_home_games_only():
    from threatwatch.collectors.schedules import parse_nhl
    body = {"games": [
        {"id": 1, "gameType": 2, "startTimeUTC": iso(NOW + timedelta(days=2)), "venue": {"default": "KeyBank Center"},
         "homeTeam": {"abbrev": "BUF"}, "awayTeam": {"abbrev": "TOR", "placeName": {"default": "Toronto"}},
         "gameCenterLink": "/gamecenter/tor-vs-buf/2026/10/22/1"},
        {"id": 2, "gameType": 2, "startTimeUTC": iso(NOW + timedelta(days=3)), "venue": "Bell Centre",
         "homeTeam": {"abbrev": "MTL"}, "awayTeam": {"abbrev": "BUF"}},
        {"id": 3, "gameType": 2, "startTimeUTC": iso(NOW + timedelta(days=30)), "venue": "KeyBank Center",
         "homeTeam": {"abbrev": "BUF"}, "awayTeam": {"abbrev": "BOS"}}]}
    ev = parse_nhl(body, TEAM_S, NOW, NOW + timedelta(days=14))
    assert [e["name"] for e in ev] == ["Sabres vs. Toronto"]
    assert ev[0]["url"].startswith("https://www.nhl.com/gamecenter/") and ev[0]["facility_id"] == "keybank_center"


def test_parse_espn_home_games_only():
    from threatwatch.collectors.schedules import parse_espn
    def g(i, days, home, away, venue="Highmark Stadium"):
        return {"id": str(i), "date": (NOW + timedelta(days=days)).strftime("%Y-%m-%dT%H:%MZ"),
                "links": [{"href": f"https://www.espn.com/nfl/game/_/gameId/{i}"}],
                "competitions": [{"venue": {"fullName": venue}, "competitors": [
                    {"homeAway": "home", "team": {"abbreviation": home, "displayName": home}},
                    {"homeAway": "away", "team": {"abbreviation": away, "displayName": "Miami Dolphins"}}]}]}
    body = {"events": [g(1, 5, "BUF", "MIA"), g(2, 9, "NYJ", "BUF", "MetLife Stadium"), g(3, 40, "BUF", "NE")]}
    ev = parse_espn(body, TEAM_B, NOW, NOW + timedelta(days=14))
    assert [e["name"] for e in ev] == ["Bills vs. Miami Dolphins"] and ev[0]["facility_id"] == "highmark_stadium"


def test_manual_events(tmp_path, monkeypatch):
    from threatwatch.collectors import schedules
    f = tmp_path / "events.yaml"
    f.write_text('events:\n  - {name: Fall Concert, site: riverworks, start: "2026-10-24 20:00"}\n'
                 '  - {name: Bad time, site: riverworks, start: "tomorrow"}\n'
                 '  - {name: Bad site, site: nowhere, start: "2026-10-24 20:00"}\n')
    monkeypatch.setattr(schedules, "EVENTS_FILE", f)
    ev = schedules.load_manual(load_facilities()["facilities"])
    assert [e["name"] for e in ev] == ["Fall Concert"]
    assert ev[0]["start_at"].startswith("2026-10-25T00:00")   # 20:00 EDT = 00:00 UTC


def test_schedules_collector_offline(monkeypatch, tmp_path):
    from threatwatch.collectors import CollectContext, schedules
    class R:
        def __init__(self, d): self.d = d
        def raise_for_status(self): pass
        def json(self): return self.d
    nhl = {"games": [{"id": 9, "gameType": 2, "startTimeUTC": iso(NOW + timedelta(days=1)), "venue": "KeyBank Center",
                      "homeTeam": {"abbrev": "BUF"}, "awayTeam": {"abbrev": "BOS"}}]}
    monkeypatch.setattr(schedules.requests, "get", lambda url, **k: R(nhl if "nhle" in url else {"events": []}))
    monkeypatch.setattr(schedules, "EVENTS_FILE", tmp_path / "none.yaml")
    store = Store(tmp_path / "s.db")
    ctx = CollectContext(load_facilities(), load_keywords(), load_sources(), store, NOW - timedelta(days=1))
    assert schedules.SchedulesCollector({"days_ahead": 14}).collect(ctx) == []
    assert len(store.events_between(NOW - timedelta(hours=6), NOW + timedelta(days=14))) == 1


def test_keyword_pack_no_sports_false_positive():
    m = Matcher(load_facilities(), load_keywords())
    for text in ["Sabres outshoot Bruins 40-22 at KeyBank Center", "Bills march down the field at Highmark Stadium",
                 "Capacity crowd expected at KeyBank Center for the home opener"]:
        assert not m.match(Post("t", "t", "1", "", text, NOW)).is_hit, text
    assert m.match(Post("t", "t", "1", "", "Lockdown at Buffalo City Hall after death threat", NOW)).is_hit


def test_area_general_only_escalates_serious(tmp_path):
    store, m = Store(tmp_path / "a.db"), Matcher(load_facilities(), load_keywords())
    _, hits = process_posts([
        Post("news", "WKBW (7 News)", "c", "https://x/c", "Fatal crash on Camp Road kills Buffalo woman",
             NOW - timedelta(hours=1), reliability="B", is_local=True),
        Post("news", "WKBW (7 News)", "d", "https://x/d", "Shooting on Buffalo's East Side leaves two injured",
             NOW - timedelta(hours=1), reliability="B", is_local=True)], store, m, load_sources())
    by_text = {h.post.native_id: h for h in hits if h.facility_id == "area_general"}
    assert by_text["c"].tier == "LOG" and by_text["d"].tier in ("WATCH", "ALERT")
