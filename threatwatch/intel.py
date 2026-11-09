"""Analysis built on stored data: briefing, change detection, data health and facility summaries.

Rules this module follows so the dashboard never overstates what it knows:
  * Every sentence is generated from counts in the database; nothing is invented.
  * Scores are priority scores (review urgency), never described as probabilities.
  * Observation, interpretation and unknowns are kept separate.
  * Changes always show the underlying counts; percentages only when the earlier count is 3+;
    with less than two full periods of collection the comparison says there isn't enough history.
  * A missing or failing source is a monitoring gap, not evidence that nothing happened.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from .geo import nearest_facility
from .models import ALERT_TIERS, REVIEW_TIERS, tier_rank
from .store import INACTIVE, OPEN, STATUS_LABEL

COVERAGE = {
    "news": "Google News and Bing News search per site, threat-term sweeps for Buffalo/Erie County, and 8 local outlet feeds. Published stories only, usually 30 min to hours after events.",
    "gdelt": "GDELT global news index (updated every 15 min): national, trade and international outlets the news search misses. Headlines only.",
    "tfr": "FAA temporary flight restrictions over the Buffalo area (VIP visits, security, hazards). The standing NFL stadium restriction is permanent and not listed.",
    "mastodon": "Public Mastodon posts with Buffalo hashtags. Small audience; useful as an extra open channel.",
    "nws": "NWS alerts for Erie County (NYC029) and the Buffalo Lake Erie marine zone (LEZ020).",
    "bluesky": "Public Bluesky posts that name a site. Small share of local social media.",
    "opendata": "Buffalo Police incidents inside site geofences. City of Buffalo only (not Orchard Park or Getzville). Published with a lag of a day or more.",
    "ny511": "NYSDOT crashes, closures and incidents within ~0.4 km of a site.",
    "schedules": "Sabres home games (NHL) and Bills home games (ESPN), plus events you add. Other venues need manual entries or Ticketmaster.",
    "events": "Ticketmaster events within 25 miles, matched to the nearest site.",
    "telegram": "Only the public channels listed in sources.yaml.",
    "youtube": "Videos geotagged near sites plus keyword searches. Many videos have no location.",
    "adsb": "Aircraft broadcasting ADS-B within 15 nm. Snapshot at scan time. Consumer drones and some police/military aircraft are not visible.",
    "ais": "Vessels broadcasting AIS on the harbor and Black Rock Canal during a 60-second listen. Many small boats carry no AIS.",
    "reddit": "Local subreddits (needs API approval).",
    "x": "X posts naming sites (pay-per-use).",
}
STATE_WORD = {"ok": "Working", "empty": "Working, no new items", "error": "Not reachable",
              "not_configured": "Not set up", None: "Not run yet"}
STALE_HOURS = 26     # two scans a day: anything older means a scan was missed


def _iso(s): return datetime.fromisoformat(s)


def _hits(store, start, end, min_tier="WATCH", include_inactive=False):
    return [dict(r) for r in store.hits_between(start, end, min_tier, include_dismissed=include_inactive)]


def collapse(rows: list[dict]) -> list[dict]:
    """One entry per report: a post that names two sites becomes one item listing both (keeps the first,
    i.e. highest-ranked, row and adds also_sites)."""
    seen, out = {}, []
    for r in rows:
        k = r.get("post_uid")
        if k in seen:
            seen[k]["also_sites"].append(r["facility_id"])
            continue
        r = dict(r)
        r["also_sites"] = []
        seen[k] = r
        out.append(r)
    return out


def _plural(n, word, plural=None):
    return f"{n} {word if n == 1 else (plural or word + 's')}"


# ------------------------------------------------------------------ data health
def data_health(store, sources_cfg: dict, now: datetime) -> list[dict]:
    health = store.source_health()
    out = []
    for name, cfg in sources_cfg.get("sources", {}).items():
        h = health.get(name)
        enabled = bool(cfg.get("enabled"))
        state = h["state"] if h else None
        last_ok = h["last_success"] if h else None
        age_h = (now - _iso(last_ok)).total_seconds() / 3600 if last_ok else None
        stale = enabled and state in ("ok", "empty") and age_h is not None and age_h > STALE_HOURS
        if not enabled:
            status, level = "Off", "off"
        elif state == "error":
            status, level = "Not reachable", "bad"
        elif state == "not_configured":
            status, level = "Not set up", "warn"
        elif state is None:
            status, level = "Not run yet", "warn"
        elif stale:
            status, level = f"Stale, last success {int(age_h)} h ago", "warn"
        else:
            status, level = STATE_WORD[state], "good"
        out.append({"name": name, "enabled": enabled, "status": status, "level": level, "state": state,
                    "last_success": last_ok, "last_attempt": h["last_attempt"] if h else None,
                    "items": h["last_items"] if h else 0, "latest_item_at": h["latest_item_at"] if h else None,
                    "error": h["last_error"] if h else "", "coverage": COVERAGE.get(name, "")})
    return out


def coverage_level(health: list[dict]) -> str:
    on = [h for h in health if h["enabled"]]
    good = [h for h in on if h["level"] == "good"]
    if not on or not good:
        return "None"
    return "Full" if len(good) == len(on) else "Partial"


# ------------------------------------------------------------------ change detection
def _enough_history(store, now, hours) -> bool:
    first = store.conn.execute("SELECT MIN(started_at) FROM scans WHERE finished_at IS NOT NULL").fetchone()[0]
    return bool(first) and _iso(first) <= now - timedelta(hours=2 * hours)


def compare(prev: int, cur: int) -> str:
    """Plain-language change that always shows counts."""
    diff = cur - prev
    if prev == cur:
        return f"{cur} vs {prev}, no change"
    sign = "+" if diff > 0 else "−"
    if prev >= 3:
        return f"{cur} vs {prev} ({sign}{abs(diff)}, {sign}{abs(diff) / prev:.0%})"
    return f"{cur} vs {prev} ({sign}{abs(diff)}; too few earlier items for a percentage)"


def changes(store, matcher, now: datetime, hours: int = 24) -> dict:
    cur_s, prev_s = now - timedelta(hours=hours), now - timedelta(hours=2 * hours)
    cur = _hits(store, cur_s, now + timedelta(minutes=1))
    prev = _hits(store, prev_s, cur_s)
    enough = _enough_history(store, now, hours)

    def by(rows, key):
        c = Counter()
        for r in rows:
            for k in key(r):
                c[k] += 1
        return c

    fac_c, fac_p = by(cur, lambda r: [r["facility_id"]]), by(prev, lambda r: [r["facility_id"]])
    cat_c, cat_p = by(cur, lambda r: json.loads(r["categories"])), by(prev, lambda r: json.loads(r["categories"]))
    open_c = sum(1 for r in cur if r["status"] in OPEN)
    open_p = sum(1 for r in prev if r["status"] in OPEN)
    src_c = len({(r["source"], r["source_name"]) for r in cur})
    src_p = len({(r["source"], r["source_name"]) for r in prev})

    rows = [("Alert and Watch items", len(prev), len(cur)),
            ("Still awaiting review", open_p, open_c),
            ("Distinct sources reporting", src_p, src_c)]
    notable = []
    for fid in sorted(set(fac_c) | set(fac_p), key=lambda f: -(fac_c[f] - fac_p[f])):
        p, c = fac_p[fid], fac_c[fid]
        if c - p >= 2 or (c >= 1 and p == 0):
            fh = [r for r in cur if r["facility_id"] == fid]
            sources = len({(r["source"], r["source_name"]) for r in fh})
            caveat = ("All from one source, so this may be repeat coverage of one event."
                      if sources == 1 and c > 1 else
                      f"{_plural(sources, 'distinct source')} — review whether they describe the same event."
                      if c > 1 else "Single report, unverified.")
            notable.append({"facility_id": fid, "text": f"{matcher.facility_name(fid)}: {compare(p, c)}.",
                            "caveat": caveat})
    cats = [{"category": matcher.label(k), "text": compare(cat_p[k], cat_c[k])}
            for k in sorted(set(cat_c) | set(cat_p), key=lambda k: -cat_c[k])][:8]
    return {"hours": hours, "enough_history": enough, "rows": rows, "notable": notable[:6], "categories": cats,
            "facility_counts": {"current": dict(fac_c), "previous": dict(fac_p)}}


# ------------------------------------------------------------------ briefing
def briefing(store, matcher, sources_cfg: dict, now: datetime, days: int, demo: bool = False) -> dict:
    start = now - timedelta(days=days)
    rows = _hits(store, start, now + timedelta(minutes=1))
    open_rows = [r for r in rows if r["status"] in OPEN and r["facility_id"] in matcher.facilities]
    ranked = sorted(open_rows, key=lambda r: (tier_rank(r["tier"]), -r["score"], r["created_at"]))
    reports = collapse(ranked)                       # count reports, not report-site pairs
    alerts = [r for r in reports if r["tier"] in ALERT_TIERS]
    acts = sum(r["tier"] == "ACT" for r in reports)
    corroborated = [r for r in reports if r["corroborating"]]
    confirmed = [r for r in rows if r["status"] == "confirmed"]
    sites = defaultdict(list)
    for r in open_rows:
        sites[r["facility_id"]].append(r)
    health = data_health(store, sources_cfg, now)
    gaps = [] if demo else [h for h in health if h["enabled"] and h["level"] in ("bad", "warn")]
    ch = changes(store, matcher, now, 24)
    scans = store.conn.execute("SELECT COUNT(*) FROM scans WHERE finished_at IS NOT NULL").fetchone()[0]

    # ---- assessment: observation / interpretation / unknowns
    if scans == 0:
        observation = "No scans yet."
        interpretation, unknowns = "", "Run a scan to start collecting."
    elif not open_rows:
        observation = (f"No open Alert or Watch items at monitored sites in the last {_plural(days, 'day')}"
                       + (f"; {_plural(len(confirmed), 'item')} confirmed earlier." if confirmed else "."))
        interpretation = "Nothing needs review."
        unknowns = (f"{_plural(len(gaps), 'source')} not working." if gaps else "All enabled sources working.")
    else:
        top = sorted(sites.items(), key=lambda kv: -max(r["score"] for r in kv[1]))
        names = ", ".join(f"{matcher.facility_name(f).split(' (')[0].split(' —')[0]} ({len(v)})" for f, v in top[:3])
        observation = (f"{_plural(len(reports), 'open report')} across {_plural(len(sites), 'monitored site')}"
                       f" await review, {len(alerts)} at Alert level"
                       + (f" ({acts} marked Act now)" if acts else "") + f". Most activity: {names}.")
        single = len(reports) - len(corroborated)
        interpretation = f"{len(corroborated)} corroborated, {single} single-source."
        unknowns = ("None confirmed by an analyst yet." if not confirmed
                    else f"{_plural(len(confirmed), 'item')} confirmed; the rest unverified.")
        if gaps:
            unknowns += f" {_plural(len(gaps), 'source')} not working — coverage partial."

    priority = reports[:5]
    return {
        "metrics": {"high_priority": len(alerts), "awaiting_review": len(reports),
                    "sites_attention": len(sites), "corroborated": len(corroborated),
                    "coverage": coverage_level(health)},
        "observation": observation, "interpretation": interpretation, "unknowns": unknowns,
        "priority": priority, "changes": ch, "gaps": gaps, "scans": scans,
    }


# ------------------------------------------------------------------ facility workspace
def facility_summary(store, matcher, fid: str, now: datetime) -> dict:
    d1, d7, d14 = now - timedelta(days=1), now - timedelta(days=7), now - timedelta(days=14)
    end = now + timedelta(minutes=1)
    all_rows = [r for r in _hits(store, now - timedelta(days=3650), end, "LOG", include_inactive=True)
                if r["facility_id"] == fid]
    def window(a, b, min_watch=True):
        return [r for r in all_rows if a.isoformat() <= r["created_at"] < b.isoformat()
                and (not min_watch or r["tier"] in REVIEW_TIERS) and r["status"] not in INACTIVE]
    last24 = window(d1, end)
    cur7, prev7 = window(d7, end), window(d14, d7)
    open_items = [r for r in all_rows if r["status"] in OPEN and r["tier"] in REVIEW_TIERS]
    outcomes = Counter(STATUS_LABEL.get(r["status"], r["status"]) for r in all_rows if r["tier"] in REVIEW_TIERS)
    cats = Counter(matcher.label(c) for r in cur7 for c in json.loads(r["categories"]))
    top = max(open_items or cur7, key=lambda r: r["score"], default=None)
    events = [dict(e) for e in store.events_between(now - timedelta(hours=6), now + timedelta(days=14))
              if e["facility_id"] == fid]
    nearby = []
    for p in store.geo_posts(("opendata", "ny511"), d7):
        near = nearest_facility(p["lat"], p["lon"], matcher.facilities, max_km=2.0)
        if near and near[0] == fid:
            nearby.append({**dict(p), "km": near[1]})
    fp = outcomes.get("False positive", 0) + outcomes.get("Duplicate", 0)
    reviewed = sum(v for k, v in outcomes.items() if k not in ("New", "In review"))
    return {"last24": last24, "open": open_items, "cur7": cur7, "prev7": prev7,
            "change7": compare(len(prev7), len(cur7)), "categories": cats.most_common(),
            "outcomes": dict(outcomes), "top": top, "events": events, "nearby": nearby[:10],
            "reviewed": reviewed, "false_positive_share": (fp / reviewed) if reviewed else None}


def facility_narrative(S: dict) -> tuple[str, str, str]:
    """Observation / interpretation / unknown sentences for a facility_summary() result."""
    obs = f"Alert or Watch items, last 7 days vs the 7 days before: {S['change7']}."
    srcs = len({(r["source"], r["source_name"]) for r in S["cur7"]})
    if not S["cur7"]:
        interp = "No recent activity to interpret."
    else:
        interp = f"They come from {_plural(srcs, 'distinct source')}"
        interp += ("; a single source can mean repeat coverage of one event." if srcs == 1 and len(S["cur7"]) > 1 else ".")
        if S["false_positive_share"] is not None:
            interp += (f" Analysts judged {S['false_positive_share']:.0%} of reviewed items here false positives "
                       "or duplicates.")
    conf = S["outcomes"].get("Confirmed", 0)
    unk = ("Whether this activity means higher operational risk to the site is not established by the data. "
           + ("No item here has been confirmed by an analyst." if not conf else f"{_plural(conf, 'item')} confirmed by an analyst."))
    return obs, interp, unk


# ------------------------------------------------------------------ rule quality from analyst outcomes
def rule_quality(store, matcher) -> list[dict]:
    """Per category: how analyst dispositions came out. Only categories with reviewed items are listed."""
    rows = store.conn.execute("SELECT categories, status FROM hits WHERE tier IN ('ACT','ALERT','WATCH')").fetchall()
    stats = defaultdict(Counter)
    for r in rows:
        for c in json.loads(r["categories"]):
            stats[c][r["status"]] += 1
    out = []
    for c, s in stats.items():
        reviewed = sum(v for k, v in s.items() if k not in OPEN)
        if not reviewed:
            continue
        fp = s["false_positive"] + s["dismissed"] + s["duplicate"]
        out.append({"category": matcher.label(c), "flagged": sum(s.values()), "reviewed": reviewed,
                    "confirmed": s["confirmed"], "false_positive_or_duplicate": fp,
                    "false_positive_share": f"{fp / reviewed:.0%}"})
    return sorted(out, key=lambda x: -x["reviewed"])
