"""One scan: collect -> dedupe/store -> match -> score -> alert -> export."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta

from .alerts import dispatch_alerts
from .collectors import CollectContext, NotConfigured, get_collectors
from .config import load_facilities, load_keywords, load_sources
from .export import write_excel
from .matcher import Matcher
from .models import REVIEW_TIERS, Hit, Post, utcnow
from .scoring import score_match
from .store import Store, window_start

log = logging.getLogger("threatwatch")
CONTEXT_SOURCES = ("schedules", "events", "gatherings")   # store scheduled events, run before the rest


@dataclass
class ScanResult:
    collected: int = 0
    new_posts: int = 0
    hits: list[Hit] = field(default_factory=list)
    alerts_sent: int = 0
    errors: dict[str, str] = field(default_factory=dict)
    not_configured: dict[str, str] = field(default_factory=dict)
    per_source: dict[str, int] = field(default_factory=dict)
    export_paths: list[str] = field(default_factory=list)
    delivery: dict = field(default_factory=dict)   # {"alerts": {...}, "summary": {...}} for the dashboard/CLI
    scan_id: int | None = None
    source_detail: dict = field(default_factory=dict)   # source -> {state, seconds, error}
    collection: list = field(default_factory=list)      # one row per collected item (see Store.log_collection)
    warnings: dict[str, str] = field(default_factory=dict)   # source -> partial problem (source still ran)
    articles: dict = field(default_factory=dict)         # {"fetched", "tried"}: full article text this scan
    kind: str = "full"                                   # "full" or "light" (hourly, fast sources only)

    def tier_counts(self) -> dict[str, int]:
        out = {"ACT": 0, "ALERT": 0, "WATCH": 0, "LOG": 0}
        for h in self.hits:
            out[h.tier] = out.get(h.tier, 0) + 1
        return out


def process_posts(posts: list[Post], store: Store, matcher: Matcher, sources_cfg: dict,
                  log: list | None = None) -> tuple[int, list[Hit]]:
    """Store new posts and turn relevant ones into scored hits. Separated out for testing.
    If `log` is given, one collection-log row per post is appended to it (new or not), in the
    analyst template's terms (see threatwatch/collection.py)."""
    from .collection import THREAT_LEVEL, analyst_initials, tool_for
    from .matcher import AREA_GENERAL
    from .models import TIER_WORD, tier_rank
    who = analyst_initials() if log is not None else ""
    tiers = sources_cfg.get("tiers", {})
    window_h = float(sources_cfg.get("scan", {}).get("corroboration_window_hours", 12))
    new, hits = 0, []
    # oldest first so corroboration builds up in time order
    now = utcnow().isoformat()
    for post in sorted(posts, key=lambda p: p.created_at):
        outcome = store.add_post_status(post)
        row = None
        if log is not None:
            row = {"collected_at": now, "source": post.source, "source_name": post.source_name, "post_uid": post.uid,
                   "published_at": post.created_at.isoformat(), "title": (post.text or "")[:2000], "url": post.url,
                   "author": post.author, "reliability": post.reliability, "outcome": outcome, "level": "",
                   "sites": "", "lat": post.lat, "lon": post.lon, "phase": "General/Industry",
                   "tool": tool_for(post.source, (post.engagement or {}).get("via", "")), "initials": who,
                   "analyst_notes": "", "threat_level": "Low", "score": None}
            log.append(row)
        if outcome != "new":
            continue
        new += 1
        m = matcher.match(post)
        if row is not None:
            named = [f for f in m.facilities if f != AREA_GENERAL]
            if named:
                row["phase"] = "Facility-Specific"
                row["sites"] = ", ".join(matcher.facility_name(f) for f in named)
            if m.threat_terms:
                terms = sorted({t for v in m.threat_terms.values() for t in v}, key=str.lower)
                row["analyst_notes"] = "Auto: terms " + ", ".join(terms[:6])
        if not m.is_hit:
            continue
        post_hits = []
        for fid in m.facilities:
            win = timedelta(hours=window_h)
            corr = store.corroborating_sources(fid, list(m.threat_terms), post.source,
                                               post.source_name, post.created_at - win,
                                               post.created_at + win)
            event_day = fid != "area_general" and store.event_near(fid, post.created_at) is not None
            hit = score_match(post, m, fid, matcher, corr, tiers, event_day)
            if store.add_hit(hit):
                hits.append(hit)
                post_hits.append(hit)
        if row is not None and post_hits:
            top = min(post_hits, key=lambda h: (tier_rank(h.tier), -h.score))
            row["level"], row["score"] = top.tier, top.score
            row["threat_level"] = THREAT_LEVEL.get(top.tier, "Low")
            row["sites"] = row["sites"] or ", ".join(matcher.facility_name(h.facility_id) for h in post_hits)
            row["analyst_notes"] = (f"Auto: {TIER_WORD[top.tier]} {top.score}/100, rating {top.admiralty}; "
                                    + row["analyst_notes"].replace("Auto: ", ""))
    store.commit()
    return new, hits


def _record(store: Store, result: "ScanResult", name: str, got=None, exc=None, seconds=0.0,
            note: str = "") -> None:
    """note: a partial problem in a source that still returned (e.g. one feed of eleven failed)."""
    if exc is None:
        n = len(got)
        if name in CONTEXT_SOURCES:   # these store events instead of returning posts
            n = int(store.get_state(f"{name}_last_count", 0) or 0)
        latest = max((p.created_at for p in got), default=None)
        result.per_source[name] = len(got)
        result.source_detail[name] = {"state": "ok" if n else "empty", "seconds": round(seconds, 1), "error": note[:300]}
        store.record_source(name, "ok" if n else "empty", n, latest.isoformat() if latest else None, error=note)
        if note:
            result.warnings[name] = note[:300]
        log.info("%s: %d items in %.1fs", name, len(got), seconds)
    elif isinstance(exc, NotConfigured):
        result.not_configured[name] = str(exc)
        result.source_detail[name] = {"state": "not_configured", "seconds": 0, "error": str(exc)[:300]}
        store.record_source(name, "not_configured", 0, error=str(exc))
        log.info("%s not configured: %s", name, exc)
    else:   # one source failing must not kill the scan
        result.errors[name] = str(exc)[:300]
        result.source_detail[name] = {"state": "error", "seconds": round(seconds, 1), "error": str(exc)[:300]}
        store.record_source(name, "error", 0, error=str(exc))
        log.warning("%s failed: %s", name, exc)


def _warnings(c) -> str:
    return "; ".join(str(w) for w in (getattr(c, "warnings", None) or []))[:300]


def collect_all(collectors, ctx: CollectContext, store: Store, result: "ScanResult",
                budget_s: float = 300, workers: int = 8) -> list[Post]:
    """Schedules/events run first (event-day context), then every other source in parallel.
    A source still running when the budget runs out is reported as timed out; the scan goes on."""
    import time
    from concurrent.futures import ThreadPoolExecutor, wait
    from dataclasses import replace

    from .store import LockedStore

    posts: list[Post] = []
    first = [c for c in collectors if c.name in CONTEXT_SOURCES]
    rest = [c for c in collectors if c not in first]
    for c in first:
        t0 = time.monotonic()
        try:
            got = c.collect(ctx)
            posts += got
            _record(store, result, c.name, got, seconds=time.monotonic() - t0, note=_warnings(c))
        except Exception as e:
            _record(store, result, c.name, exc=e)
    if not rest:
        return posts

    locked = LockedStore(store)
    store.lock = locked._lock          # run_scan holds it while scoring, in case a timed-out source still writes
    pctx = replace(ctx, store=locked)
    pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="collect")
    started, finished = {}, {}

    def run(c):
        started[c.name] = time.monotonic()
        try:
            return c.collect(pctx)
        finally:
            finished[c.name] = time.monotonic()

    futs = {pool.submit(run, c): c for c in rest}
    done, pending = wait(futs, timeout=budget_s)
    done = sorted(done, key=lambda f: futs[f].name)
    for f in done:
        c = futs[f]
        secs = finished.get(c.name, time.monotonic()) - started.get(c.name, time.monotonic())
        try:
            got = f.result()
            posts += got
            with locked._lock:
                _record(store, result, c.name, got, seconds=secs, note=_warnings(c))
        except Exception as e:
            with locked._lock:
                _record(store, result, c.name, exc=e, seconds=secs)
    for f in pending:
        with locked._lock:
            _record(store, result, futs[f].name,
                    exc=TimeoutError(f"still running after {budget_s:.0f}s; skipped this scan"))
    pool.shutdown(wait=False, cancel_futures=True)
    return posts


def light_sources_cfg(sources: dict) -> dict:
    """The source config for a light scan: only the sources listed under scan.light.sources, and news
    from the local outlet feeds only (no Google/Bing searches, which would be throttled if run hourly)."""
    import copy
    cfg = copy.deepcopy(sources)
    keep = set(cfg.get("scan", {}).get("light", {}).get("sources", []))
    for name, sc in cfg.get("sources", {}).items():
        if name not in keep:
            sc["enabled"] = False
    news = cfg.get("sources", {}).get("news")
    if news and news.get("enabled"):
        news.update(google_news=False, bing_news=False, threat_sweeps=False, extra_queries=[])
    return cfg


def light_enabled(sources: dict) -> bool:
    light = sources.get("scan", {}).get("light", {})
    return bool(light.get("enabled") and light.get("sources"))


def run_scan(send_alerts: bool = True, store: Store | None = None, light: bool = False) -> ScanResult:
    """light=True: the hourly scan between full scans (see light_sources_cfg). It still sends alerts for
    Act now / Alert items, but no scan summary email, so the inbox gets two summaries a day, not 24."""
    started = utcnow()
    facilities, keywords, sources = load_facilities(), load_keywords(), load_sources()
    if light:
        sources = light_sources_cfg(sources)
    store = store or Store()
    matcher = Matcher(facilities, keywords)
    lookback = float(sources.get("scan", {}).get("lookback_hours", 24))
    if not light:   # a full scan covers everything since the previous full scan, up to catchup_max_hours
        last_full = store.last_scan_finished("full")
        if last_full:
            gap_h = (utcnow() - last_full).total_seconds() / 3600 + 1
            lookback = max(lookback, min(gap_h, float(sources.get("scan", {}).get("catchup_max_hours", 72))))
    ctx = CollectContext(facilities, keywords, sources, store, window_start(lookback))

    result = ScanResult(kind="light" if light else "full")
    result.scan_id = store.begin_scan(started)
    all_posts = collect_all(get_collectors(sources), ctx, store, result,
                            budget_s=float(sources.get("scan", {}).get("max_seconds", 300)),
                            workers=int(sources.get("scan", {}).get("parallel_sources", 8)))
    result.collected = len(all_posts)
    try:   # read the full article for the most promising new items before matching (threatwatch/article.py)
        from .article import enrich
        result.articles = enrich(all_posts, matcher, sources.get("scan", {}).get("article_text", {}),
                                 is_new=lambda p: not store.is_stored(p))
    except Exception as e:
        result.warnings["articles"] = f"article text skipped: {str(e)[:200]}"
    lock = getattr(store, "lock", None)   # held from here on, in case a timed-out source still writes
    if lock:
        lock.acquire()
    try:
        return _finish(result, all_posts, store, matcher, sources, started, send_alerts)
    finally:
        if lock:
            lock.release()


def _finish(result, all_posts, store, matcher, sources, started, send_alerts) -> ScanResult:
    result.new_posts, result.hits = process_posts(all_posts, store, matcher, sources, log=result.collection)
    try:   # collection log: every item, plus one row per source for this scan
        per = {}
        for r in result.collection:
            d = per.setdefault(r["source"], {"items": 0, "new": 0, "flagged": 0})
            d["items"] += 1
            d["new"] += r["outcome"] == "new"
            d["flagged"] += bool(r["level"])
        rows = [{"source": n, **{"items": 0, "new": 0, "flagged": 0}, **per.get(n, {}),
                 "state": d["state"], "seconds": d["seconds"], "error": d["error"]}
                for n, d in result.source_detail.items()]
        if result.scan_id:   # each item is logged once, when first collected; repeats only count per source
            store.log_collection(result.scan_id, [r for r in result.collection if r["outcome"] == "new"], rows)
            store.prune_collection(int(sources.get("scan", {}).get("collection_log_days", 90)))
    except Exception as e:
        result.errors["collection_log"] = str(e)[:300]

    if send_alerts:
        try:
            result.alerts_sent = dispatch_alerts(store, matcher)
            result.delivery["alerts"] = {"ok": True, "sent": result.alerts_sent,
                                         "message": f"{result.alerts_sent} alert item(s) sent" if result.alerts_sent
                                         else "no new Act/Alert items to send"}
        except Exception as e:
            result.errors["alerts"] = str(e)[:300]
            result.delivery["alerts"] = {"ok": False, "sent": 0, "message": f"alert delivery failed: {str(e)[:200]}"}
    else:
        result.delivery["alerts"] = {"ok": True, "sent": 0, "message": "alerts not sent (turned off for this scan)"}

    store.log_scan(started, result.collected, result.new_posts, len(result.hits),
                   result.alerts_sent, result.errors,
                   {"per_source": result.per_source, "not_configured": result.not_configured,
                    "warnings": result.warnings, "kind": result.kind, "articles": result.articles},
                   scan_id=result.scan_id)
    try:   # Excel log of Alert/Watch items, same format every scan
        important = [h for h in result.hits if h.tier in REVIEW_TIERS]
        ids = [r["id"] for r in store.conn.execute(
            f"SELECT id FROM hits WHERE post_uid IN ({','.join('?' * len(important))})",
            [h.post.uid for h in important]).fetchall()] if important else []
        result.export_paths = [write_excel(store, matcher, ids)]
    except Exception as e:
        result.errors["excel"] = str(e)[:300]
    try:
        from .export import write_collection_excel
        result.export_paths.append(write_collection_excel(store))
    except Exception as e:
        result.errors["collection_excel"] = str(e)[:300]
    if send_alerts and result.kind == "light":
        result.delivery["summary"] = {"ok": True, "sent": False, "message": "light hourly scan: no summary email"}
    elif send_alerts:   # last, so it can report everything above (including Excel errors)
        from .alerts import send_scan_summary
        sent, msg = send_scan_summary(result, matcher)
        failed = msg.startswith("summary email failed")
        result.delivery["summary"] = {"ok": not failed, "sent": sent, "message": msg}
        if failed:
            result.errors["summary_email"] = msg[:300]
    return result


def auto_reason(store: Store, sources_cfg: dict, now=None) -> str | None:
    """For the hourly schedule: why this hour should scan, or None to skip.
    Always at the base hours (07:00, 15:00 local); otherwise only around events or after an alert."""
    from datetime import datetime
    from zoneinfo import ZoneInfo

    cfg = sources_cfg.get("scan", {})
    now = now or utcnow()
    local = now.astimezone(ZoneInfo(cfg.get("timezone", "America/New_York")))
    if local.hour in cfg.get("base_hours", [7, 15]):
        return f"scheduled {local:%H}:00 scan"
    last = store.last_scan_finished()
    gap_h = (now - last).total_seconds() / 3600 if last else None
    if gap_h is not None and gap_h > float(cfg.get("catchup_after_hours", 2)):
        return f"catching up: no scan for {gap_h:.0f} h (computer asleep or offline)"
    ev = store.events_between(now - timedelta(hours=float(cfg.get("event_after_hours", 3))),
                              now + timedelta(hours=float(cfg.get("event_before_hours", 6))))
    if ev:
        return f"event window: {ev[0]['name']}"
    recent = store.conn.execute(
        "SELECT COUNT(*) FROM hits h JOIN posts p ON p.uid=h.post_uid WHERE h.tier IN ('ACT','ALERT') "
        "AND h.status IN ('new','in_review') AND p.created_at >= ?",
        ((now - timedelta(hours=float(cfg.get("alert_followup_hours", 6)))).isoformat(),)).fetchone()[0]
    if recent:
        return f"{recent} open alert(s) in the last 6 h"
    return None


def rescore(store: Store, days: float = 7) -> dict:
    """Re-run matching and scoring on unreviewed hits from the last `days` with the current rules.
    Scores, tiers and explanations are updated; a hit that no longer matches its site is closed with a
    note. Anything an analyst has touched (status other than New) is left alone."""
    import json
    from datetime import datetime

    matcher = Matcher(load_facilities(), load_keywords())
    sources = load_sources()
    tiers, window_h = sources.get("tiers", {}), float(sources.get("scan", {}).get("corroboration_window_hours", 12))
    rows = store.conn.execute(
        "SELECT h.id, h.facility_id, h.tier, p.* FROM hits h JOIN posts p ON p.uid=h.post_uid "
        "WHERE h.status='new' AND p.created_at >= ?", (window_start(days * 24).isoformat(),)).fetchall()
    out = {"checked": len(rows), "changed": 0, "closed": 0}
    for r in rows:
        post = Post(r["source"], r["source_name"], r["native_id"], r["url"], r["text"],
                    datetime.fromisoformat(r["created_at"]), r["author"] or "", r["reliability"] or "D",
                    bool(r["is_local"]), lat=r["lat"], lon=r["lon"],
                    body=(r["body"] if "body" in r.keys() else "") or "")
        m = matcher.match(post)
        if not m.is_hit or r["facility_id"] not in m.facilities:
            store.update_hit(r["id"], status="closed", note="Closed automatically: no longer matches the current rules.",
                             reviewer="rescore")
            out["closed"] += 1
            continue
        win = timedelta(hours=window_h)
        corr = store.corroborating_sources(r["facility_id"], list(m.threat_terms), post.source, post.source_name,
                                           post.created_at - win, post.created_at + win)
        ev = r["facility_id"] != "area_general" and store.event_near(r["facility_id"], post.created_at) is not None
        h = score_match(post, m, r["facility_id"], matcher, corr, tiers, ev)
        if h.tier != r["tier"]:
            out["changed"] += 1
        store.conn.execute("UPDATE hits SET score=?, tier=?, admiralty=?, corroborating=?, categories=?, terms=?, "
                           "factors=? WHERE id=?", (h.score, h.tier, h.admiralty, h.corroborating_sources,
                                                    json.dumps(h.categories), json.dumps(h.terms),
                                                    json.dumps(h.factors), r["id"]))
    store.commit()
    return out


def online(hosts=("news.google.com", "api.weather.gov"), tries: int = 4, wait_s: float = 30) -> bool:
    """True once any host resolves. Waits between tries, for a Mac that's just waking from sleep."""
    import socket
    import time
    for attempt in range(max(1, tries)):
        if attempt:
            time.sleep(wait_s)
        for h in hosts:
            try:
                socket.getaddrinfo(h, 443)
                return True
            except OSError:
                continue
    return False
