"""GDELT: a global index of online news, updated every 15 minutes. Free, no key.

Catches outlets that Google/Bing News and the local feeds miss (trade press, national and
international sites). Two modes (sources.yaml, gdelt.mode):

- "events" (default): the raw 15-minute GDELT 2.0 event files. Each event is machine-coded from an
  article (who did what to whom, CAMEO code) and geocoded. We keep threat-type events located within
  `radius_km` of Buffalo and turn each article into one item. Plain file downloads: no rate limit.
- "doc": the DOC 2.0 search API. It throttles by IP (one request per 5 s, and it often answers 429
  even then), so it is kept only as a fallback.
"""
from __future__ import annotations

import csv
import io
import math
import re
import time
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlparse

import requests

from .. import http

from ..models import Post
from . import CollectContext
from .news import ESTABLISHED, UA, chunks, title_key

API = "https://api.gdeltproject.org/api/v2/doc/doc"
FILES = "https://data.gdeltproject.org/gdeltv2"
BUFFALO = (42.8864, -78.8784)
# CAMEO root codes worth a security analyst's attention, and how each reads in an item
ROOTS = {"13": "threaten", "14": "protest", "15": "show of force", "16": "reduce relations",
         "17": "coerce", "18": "assault", "19": "fight", "20": "mass violence"}
# GDELT 2.0 event file columns (0-based)
C_ACTOR1, C_ACTOR2, C_ROOT, C_GEO_NAME, C_GEO_ADM1 = 6, 16, 28, 52, 54
C_LAT, C_LON, C_ADDED, C_URL = 56, 57, 59, 60


def km_between(a: tuple[float, float], b: tuple[float, float]) -> float:
    la1, lo1, la2, lo2 = map(math.radians, (*a, *b))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


def headline_from_url(url: str) -> str:
    """Most news URLs end in a slug of the headline: /2026/11/09/man-charged-in-elmwood-shooting/."""
    parts = [p for p in urlparse(url).path.split("/") if p]
    for seg in reversed(parts):
        seg = re.sub(r"\.(s?html?|php|aspx?)$", "", unquote(seg), flags=re.I)
        words = [w for w in re.split(r"[-_+]+", seg) if w and not re.fullmatch(r"[0-9a-f]{6,}|\d+|amp|index", w, re.I)]
        if len(words) >= 3:
            return " ".join(words).capitalize()
    return ""


def file_stamps(start: datetime, end: datetime) -> list[str]:
    """15-minute GDELT file stamps (YYYYMMDDHHMMSS) after `start` up to and including `end`."""
    t = start.replace(second=0, microsecond=0)
    t -= timedelta(minutes=t.minute % 15)
    out = []
    while t < end:
        t += timedelta(minutes=15)
        if t <= end:
            out.append(t.strftime("%Y%m%d%H%M%S"))
    return out


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
        if self.cfg.get("mode", "events") == "doc":
            return self.collect_doc(ctx)
        return self.collect_events(ctx)

    # ---- events mode: raw 15-minute files -------------------------------------------------------
    def latest_stamp(self) -> datetime:
        r = http.get(f"{FILES}/lastupdate.txt", headers={"User-Agent": UA}, timeout=20)
        r.raise_for_status()
        m = re.search(r"/(\d{14})\.export\.CSV\.zip", r.text)
        if not m:
            raise RuntimeError(f"GDELT: unexpected lastupdate.txt ({r.text[:80]!r})")
        return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)

    def read_file(self, stamp: str) -> list[list[str]]:
        r = http.get(f"{FILES}/{stamp}.export.CSV.zip", headers={"User-Agent": UA}, timeout=40, tries=2)
        if r.status_code == 404:       # GDELT occasionally skips a 15-minute slot
            return []
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            raw = z.read(z.namelist()[0]).decode("utf-8", "replace")
        return list(csv.reader(io.StringIO(raw), delimiter="\t"))

    def keep(self, row: list[str]) -> bool:
        if len(row) <= C_URL or row[C_ROOT] not in self.roots:
            return False
        if row[C_GEO_ADM1] != "USNY":
            return False
        try:
            here = (float(row[C_LAT]), float(row[C_LON]))
        except ValueError:
            return False
        return km_between(here, self.center) <= self.radius_km

    def collect_events(self, ctx: CollectContext) -> list[Post]:
        self.center = tuple(self.cfg.get("center", BUFFALO))
        self.radius_km = float(self.cfg.get("radius_km", 40))
        self.roots = {str(c) for c in self.cfg.get("root_codes", ROOTS)}
        latest = self.latest_stamp()
        done = ctx.store.get_state("gdelt_last_file")
        start = max(ctx.since, latest - timedelta(minutes=15 * int(self.cfg.get("max_files", 16))))
        if done:
            start = max(start, datetime.strptime(done, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc))
        stamps = file_stamps(start, latest)
        by_url: dict[str, dict] = {}
        self.warnings, read = [], 0
        for stamp in stamps:
            try:
                rows = self.read_file(stamp)
            except Exception as e:
                self.warnings.append(f"file {stamp[8:12]} UTC: {str(e)[:60]}")
                continue
            read += 1
            for row in rows:
                if not self.keep(row):
                    continue
                url = row[C_URL]
                item = by_url.setdefault(url, {"kinds": [], "place": row[C_GEO_NAME], "actors": set(),
                                                "added": row[C_ADDED]})
                kind = ROOTS.get(row[C_ROOT], row[C_ROOT])
                if kind not in item["kinds"]:
                    item["kinds"].append(kind)
                item["actors"].update(a.title() for a in (row[C_ACTOR1], row[C_ACTOR2]) if a)
        if stamps and not read:
            raise RuntimeError(f"GDELT: none of {len(stamps)} event files could be read ({self.warnings[0]})")
        if stamps:
            ctx.store.set_state("gdelt_last_file", stamps[-1])
        posts = []
        for url, it in by_url.items():
            try:
                when = datetime.strptime(it["added"], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
            except ValueError:
                when = datetime.now(timezone.utc)
            domain = urlparse(url).netloc.replace("www.", "")
            title = headline_from_url(url)
            who = f" involving {', '.join(sorted(it['actors'])[:3])}" if it["actors"] else ""
            text = (f"{title + '. ' if title else ''}News report coded by GDELT as {' / '.join(it['kinds'])}"
                    f"{who}, located in {it['place']}.")
            posts.append(Post(
                source="gdelt", source_name=domain, native_id=url, url=url, text=text,
                created_at=max(when, ctx.since), reliability="B" if ESTABLISHED.search(domain) else "C",
                engagement={"via": "GDELT 2.0 event files", "cameo": it["kinds"]}))
        return posts

    # ---- doc mode: DOC 2.0 search API (fallback) ------------------------------------------------
    def collect_doc(self, ctx: CollectContext) -> list[Post]:
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
