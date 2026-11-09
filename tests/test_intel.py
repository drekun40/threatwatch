"""Briefing, change detection, audit trail, statuses, source health and report types."""
from datetime import datetime, timedelta, timezone

from docx import Document

from threatwatch import intel
from threatwatch.config import load_facilities, load_keywords, load_sources
from threatwatch.matcher import Matcher
from threatwatch.models import Post
from threatwatch.pipeline import process_posts
from threatwatch.store import Store

NOW = datetime.now(timezone.utc)


def seed(tmp_path):
    s, m = Store(tmp_path / "i.db"), Matcher(load_facilities(), load_keywords())
    s.log_scan(NOW - timedelta(hours=60), 0, 0, 0, 0, {})
    posts = [Post("news", "WGRZ (NBC 2)", "a", "https://www.wgrz.com/a", "Bomb threat at Buffalo City Hall, evacuated",
                  NOW - timedelta(hours=2), reliability="B", is_local=True),
             Post("news", "WKBW (7 News)", "b", "https://www.wkbw.com/b", "Buffalo City Hall evacuated after a bomb threat",
                  NOW - timedelta(hours=1), reliability="B", is_local=True),
             Post("bluesky", "Bluesky", "c", "https://bsky.app/c", "Fight outside Canalside tonight",
                  NOW - timedelta(hours=30))]
    process_posts(posts, s, m, load_sources())
    return s, m


def test_briefing_is_data_driven(tmp_path):
    s, m = seed(tmp_path)
    b = intel.briefing(s, m, load_sources(), NOW, 7)
    assert b["metrics"]["awaiting_review"] >= 2 and b["metrics"]["sites_attention"] >= 1
    assert "corroborated" in b["interpretation"] and "single-source" in b["interpretation"]
    assert "None confirmed" in b["unknowns"]
    assert b["priority"][0]["facility_id"] == "city_hall"


def test_briefing_empty_says_so(tmp_path):
    b = intel.briefing(Store(tmp_path / "e.db"), Matcher(load_facilities(), load_keywords()), load_sources(), NOW, 7)
    assert "No scans yet" in b["observation"]


def test_compare_handles_small_and_zero():
    assert "too few" in intel.compare(0, 5)
    assert "+75%" in intel.compare(4, 7)
    assert "no change" in intel.compare(2, 2)


def test_changes_baseline(tmp_path):
    s, m = seed(tmp_path)
    ch = intel.changes(s, m, NOW, 24)
    assert ch["enough_history"]
    assert any(n["facility_id"] == "city_hall" for n in ch["notable"])
    s2 = Store(tmp_path / "n.db")
    s2.log_scan(NOW - timedelta(hours=2), 0, 0, 0, 0, {})
    assert not intel.changes(s2, m, NOW, 24)["enough_history"]


def test_audit_trail_and_inactive(tmp_path):
    s, m = seed(tmp_path)
    hid = s.conn.execute("SELECT id FROM hits WHERE facility_id='canalside'").fetchone()[0]
    s.update_hit(hid, status="in_review", note="checking")
    s.update_hit(hid, status="false_positive", note="sports article")
    hist = s.history(hid)
    assert [h["new_status"] for h in hist] == ["false_positive", "in_review"]
    assert hist[0]["old_status"] == "in_review"
    ids = [r["id"] for r in s.hits_between(NOW - timedelta(days=3), NOW + timedelta(minutes=1))]
    assert hid not in ids                       # false positives leave the active views
    s.update_hit(hid, status="false_positive", note="sports article")   # no-op change is not logged twice
    assert len(s.history(hid)) == 2


def test_score_factors_and_related(tmp_path):
    s, m = seed(tmp_path)
    rows = s.conn.execute("SELECT id, factors, score FROM hits WHERE facility_id='city_hall' ORDER BY id").fetchall()
    import json
    f = json.loads(rows[1]["factors"])
    assert any("Severity" in t for t, _ in f)
    assert max(0, min(100, sum(p for _, p in f))) == rows[1]["score"]
    rel = s.related(rows[1]["id"])
    assert len(rel) == 1 and rel[0]["same_source"] == 0


def test_source_health_states(tmp_path):
    s = Store(tmp_path / "h.db")
    s.record_source("news", "ok", 10, NOW.isoformat())
    s.record_source("news", "error", 0, error="timeout")
    h = s.source_health()["news"]
    assert h["state"] == "error" and h["last_success"] is not None and h["last_error"] == "timeout"
    rows = {x["name"]: x for x in intel.data_health(s, load_sources(), NOW)}
    assert rows["news"]["level"] == "bad" and rows["nws"]["status"] == "Not run yet"


def test_report_kinds(tmp_path, monkeypatch):
    from threatwatch import report
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    s, m = seed(tmp_path)
    hid = s.conn.execute("SELECT id FROM hits LIMIT 1").fetchone()[0]
    for kind, kw in [("executive", {}), ("analyst", {}), ("facility", {"facility_ids": ["city_hall"]}),
                     ("selected", {"hit_ids": [hid]})]:
        path = report.build_report(kind, store=s, days=7, **kw)
        text = "\n".join(p.text for p in Document(path).paragraphs)
        assert "Generated" in text and "Data coverage" in text, kind
        if kind == "executive":
            assert "Recommended follow-up" in text and "What we don't know" in text
        if kind == "facility":
            assert "Observation:" in text and "Buffalo City Hall" in text
        if kind in ("analyst", "selected"):
            assert "not a probability" in text
