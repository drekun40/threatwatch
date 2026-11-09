"""GDELT DOC 2.0: a global index of online news, updated every 15 minutes. Free, no key.

Catches outlets that Google/Bing News and the local feeds miss (trade press, national and
international sites). Titles only. GDELT asks for at most one request every 5 seconds.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

from .. import http

from ..models import Post
from . import CollectContext
from .news import ESTABLISHED, UA, chunks, title_key

API = "https://api.gdeltproject.org/api/v2/doc/doc"


class GDELTCollector:
    name = "gdelt"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def queries(self, ctx: CollectContext) -> list[str]:
        names = []
        for fac in ctx.facilities.get("facilities", []):
            names += [t for t in ctx.facility_search_terms(fac, n=1) if len(t) > 4]
        out = ["(" + " OR ".join(f'"{n}"' for n in g) + ") Buffalo" for g in chunks(list(dict.fromkeys(names)), 14)]
        sweep = [t for t in dict.fromkeys(ctx.high_severity_terms(min_weight=10)) if len(t) > 4]
        out += ["(" + " OR ".join(f'"{t}"' for t in g) + ') "Buffalo"' for g in chunks(sweep, 12)]
        return out + list(self.cfg.get("extra_queries", []))

    def collect(self, ctx: CollectContext) -> list[Post]:
        # GDELT throttles by IP. After a 429 we wait before trying again instead of hammering it.
        nxt = ctx.store.get_state("gdelt_next_ok")
        if nxt and datetime.fromisoformat(nxt) > datetime.now(timezone.utc):
            self.errors = [f"backing off after a rate limit; next try after {nxt[11:16]} UTC"]
            return []
        last = ctx.store.get_state("gdelt_last_run")
        every_h = float(self.cfg.get("min_interval_hours", 3))
        if last and datetime.fromisoformat(last) > datetime.now(timezone.utc) - timedelta(hours=every_h):
            self.errors = [f"runs every {every_h:g} h to stay under GDELT's limit; last run {last[11:16]} UTC"]
            return []
        ctx.store.set_state("gdelt_last_run", datetime.now(timezone.utc).isoformat())
        hours = max(1, int((datetime.now(timezone.utc) - ctx.since).total_seconds() // 3600))
        posts, seen, errors, qs = [], set(), [], self.queries(ctx)
        deadline = time.monotonic() + float(self.cfg.get("max_seconds", 120))
        streak = 0
        for i, q in enumerate(qs):
            if streak >= 2 or time.monotonic() > deadline:   # GDELT is throttling or slow: keep what we have
                errors.append(f"stopped after {i} of {len(qs)} queries (rate-limited or slow)")
                break
            if i:
                time.sleep(float(self.cfg.get("pause_seconds", 6)))
            try:
                r = http.get(API, headers={"User-Agent": UA}, timeout=20, params={
                    "query": f"{q} sourcelang:english", "mode": "artlist", "format": "json",
                    "maxrecords": int(self.cfg.get("max_records", 75)), "timespan": f"{hours}h",
                    "sort": "datedesc"})
                r.raise_for_status()
                arts = r.json().get("articles", []) if r.text.strip().startswith("{") else []
                if not r.text.strip().startswith("{"):
                    errors.append(r.text.strip()[:120])
                streak = 0
            except Exception as e:
                errors.append(str(e)[:120])
                if "429" in str(e):
                    wait_min = int(self.cfg.get("backoff_minutes", 45))
                    ctx.store.set_state("gdelt_next_ok", (datetime.now(timezone.utc)
                                                          + timedelta(minutes=wait_min)).isoformat())
                    errors.append(f"rate-limited by GDELT; pausing it for {wait_min} min")
                    break
                streak += 1
                continue
            for a in arts:
                key = title_key(a.get("title", ""))
                if not a.get("url") or key in seen:
                    continue
                seen.add(key)
                try:
                    when = datetime.strptime(a["seendate"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                except Exception:
                    when = datetime.now(timezone.utc)
                if when < ctx.since:
                    continue
                domain = a.get("domain") or urlparse(a["url"]).netloc
                posts.append(Post(
                    source="gdelt", source_name=domain, native_id=a["url"], url=a["url"],
                    text=" ".join(a.get("title", "").split()), created_at=when,
                    reliability="B" if ESTABLISHED.search(domain) else "C"))
        self.errors = errors
        if errors and not posts and len(errors) >= min(len(qs), 2):
            raise RuntimeError(f"GDELT: {errors[-1]} ({errors[0][:80]})")
        if errors:
            import logging
            logging.getLogger("threatwatch").warning("gdelt: %s", errors[-1])
        return posts
