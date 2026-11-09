"""Offline tests: matching, scoring, dedupe, corroboration, export and report — no network needed."""
from datetime import datetime, timedelta, timezone

import pytest

from threatwatch.config import load_facilities, load_keywords, load_sources
from threatwatch.matcher import AREA_GENERAL, Matcher
from threatwatch.models import Post
from threatwatch.pipeline import process_posts
from threatwatch.store import Store

NOW = datetime.now(timezone.utc)


def post(text, source="bluesky", name="Bluesky", rel="D", local=False, mins_ago=30, nid=None):
    return Post(source, name, nid or str(abs(hash((text, source, name)))), f"https://ex.com/{abs(hash(text))}",
                text, NOW - timedelta(minutes=mins_ago), reliability=rel, is_local=local)


@pytest.fixture
def m():
    return Matcher(load_facilities(), load_keywords())


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "t.db")


def test_facility_and_threat_match(m):
    r = m.match(post("Shots fired near Canalside after the concert"))
    assert "canalside" in r.facilities
    assert "weapons_violence" in r.threat_terms
    assert "concert" in [c.lower() for c in r.context_terms]


def test_plurals(m):
    r = m.match(post("Multiple fights broke out at Sahlen Field tonight"))
    assert r.threat_terms["weapons_violence"] == ["fights"]


def test_ambiguous_alias_needs_context(m):
    assert "keybank_center" not in m.match(post("Big fight outside the Arena")).facilities
    assert "keybank_center" in m.match(post("Big fight outside the Arena in Buffalo")).facilities


def test_area_general(m):
    r = m.match(post("Shooting reported on the East Side of Buffalo"))
    assert r.facilities == [AREA_GENERAL]


def test_no_hit_without_threat(m):
    assert not m.match(post("Great hot dogs at the Broadway Market today")).is_hit


def test_context_only_never_triggers(m):
    assert not m.match(post("Boat parade on the waterfront at Canalside")).is_hit


def test_scoring_and_corroboration(m, store):
    cfg = load_sources()
    p1 = post("Bomb threat reported at Buffalo City Hall, building evacuated", mins_ago=60)
    new, hits = process_posts([p1], store, m, cfg)
    h1 = [h for h in hits if h.facility_id == "city_hall"][0]
    assert h1.tier == "ALERT" and h1.admiralty == "D4"

    p2 = post("Buffalo City Hall evacuated over bomb threat, police say", source="news",
              name="WGRZ (NBC 2)", rel="B", local=True, mins_ago=20)
    _, hits2 = process_posts([p2], store, m, cfg)
    h2 = [h for h in hits2 if h.facility_id == "city_hall"][0]
    assert h2.corroborating_sources == 1 and h2.admiralty == "B3"
    assert h2.score > h1.score


def test_dedupe(m, store):
    p = post("Fight at Canalside", nid="1")
    dup = post("Fight at Canalside", nid="2")      # same text, same source -> repost
    new, hits = process_posts([p, dup, p], store, m, load_sources())
    assert new == 1 and len(hits) == 1


def test_report_and_export(m, store, tmp_path, monkeypatch):
    from threatwatch import export
    from threatwatch.report import build_weekly_report
    monkeypatch.setattr(export, "XLSX", tmp_path / "log.xlsx")
    _, hits = process_posts([post("Suspicious package at the Federal Courthouse in Buffalo")],
                            store, m, load_sources())
    assert export.write_excel(store, m).endswith(".xlsx")
    assert build_weekly_report(days=7, store=store).endswith(".docx")
