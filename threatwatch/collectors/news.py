"""News collection, as wide as free sources allow:

  - Google News RSS search per facility (site names + Buffalo)
  - Bing News RSS search per facility (second index; links decoded to the publisher's own URL)
  - threat sweeps: high-severity terms + Buffalo on both engines
  - local outlet RSS feeds (config/sources.yaml)

Requests run in parallel. The same story found by several engines is kept once.
"""
from __future__ import annotations

import calendar
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html import unescape
from urllib.parse import parse_qs, quote_plus, urlparse

import feedparser
import requests

from .. import http

from ..models import Post
from . import CollectContext

log = logging.getLogger("threatwatch")

# outlets treated as established (B); everything else found by a search engine is C
ESTABLISHED = re.compile(
    r"wgrz|wkbw|wivb|buffalo news|buffalonews|investigative post|spectrum|wbfo|btpm|associated press|"
    r"\bap\b|apnews|reuters|nbc|cbs|abc|cnn|new york times|nytimes|wall street journal|wsj|buffalo rising|"
    r"buffalorising|wben|buffalo business first|bizjournals|niagara gazette|lockport journal|"
    r"democrat ?(and|&) ?chronicle|syracuse|newsday|times union|politico|npr|fox", re.I)
UA = "ThreatWatch/0.2 (facility security monitoring; contact via repo owner)"


def _clean(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html or "")).split())


def _when(entry) -> datetime:
    t = entry.get("published_parsed") or entry.get("updated_parsed")
    if t:
        return datetime.fromtimestamp(calendar.timegm(t), tz=timezone.utc)
    return datetime.now(timezone.utc)


def bing_target(link: str) -> str:
    """Bing wraps results in a click-tracking URL; the publisher's address is in its url= parameter."""
    try:
        q = parse_qs(urlparse(link).query)
        if "url" in q and q["url"][0].startswith("http"):
            return q["url"][0]
    except Exception:
        pass
    return link


def title_key(title: str) -> str:
    """Normalized headline used to drop the same story found by several engines."""
    t = re.sub(r"\s+[-–|]\s+[^-–|]{2,60}$", "", title or "")      # drop " - Outlet" suffix
    return re.sub(r"[^a-z0-9]+", " ", t.lower()).strip()[:90]


def chunks(items: list, n: int):
    for i in range(0, len(items), n):
        yield items[i:i + n]


class NewsCollector:
    name = "news"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def _fetch(self, url: str):
        # requests (certifi CA bundle) instead of feedparser's urllib, which fails with
        # CERTIFICATE_VERIFY_FAILED on python.org builds of Python for macOS.
        try:
            r = http.get(url, headers={"User-Agent": UA}, timeout=15)
            r.raise_for_status()
            d = feedparser.parse(r.content)
            if d.get("bozo") and not d.entries:
                return url, d, str(d.get("bozo_exception"))
            return url, d, None
        except Exception as e:
            return url, feedparser.FeedParserDict(entries=[]), str(e)

    # ---- query plan ------------------------------------------------------------
    def plan(self, ctx: CollectContext) -> list[dict]:
        """Every request this scan will make: {url, engine, local, name, reliability}."""
        reqs = []
        window = self.cfg.get("google_window", "1d")
        engines = []
        if self.cfg.get("google_news", True):
            engines.append("google")
        if self.cfg.get("bing_news", True):
            engines.append("bing")

        def search(engine, q):
            if engine == "google":
                return ("https://news.google.com/rss/search?q=" + quote_plus(f"{q} when:{window}")
                        + "&hl=en-US&gl=US&ceid=US:en")
            return "https://www.bing.com/news/search?format=rss&qft=sortbydate%3d%221%22&q=" + quote_plus(q)

        queries = []
        for fac in ctx.facilities.get("facilities", []):
            terms = ctx.facility_search_terms(fac, n=int(self.cfg.get("names_per_site", 3)))
            if not terms:
                continue
            q = " OR ".join(f'"{t}"' for t in terms)
            if fac["id"] not in ("highmark_stadium", "jcc_getzville"):
                q = f"({q}) Buffalo"
            queries.append(q)
        # threat sweeps: catch incidents that name a street or block rather than the site
        if self.cfg.get("threat_sweeps", True):
            terms = ctx.high_severity_terms(min_weight=int(self.cfg.get("sweep_min_weight", 8)))
            terms = [t for t in dict.fromkeys(terms) if len(t) > 3]
            for group in chunks(terms, 8):
                queries.append("(" + " OR ".join(f'"{t}"' for t in group) + ') ("Buffalo" OR "Erie County")')
        for q in queries + list(self.cfg.get("extra_queries", [])):
            for eng in engines:
                reqs.append({"url": search(eng, q), "engine": eng, "local": False})
        for feed in self.cfg.get("feeds", []):
            reqs.append({"url": feed["url"], "engine": "feed", "local": True, "name": feed["name"],
                         "reliability": feed.get("reliability", "B")})
        return reqs

    # ---- collect ---------------------------------------------------------------
    def collect(self, ctx: CollectContext) -> list[Post]:
        reqs = self.plan(ctx)
        by_url = {r["url"]: r for r in reqs}
        with ThreadPoolExecutor(max_workers=int(self.cfg.get("parallel", 8))) as pool:
            results = list(pool.map(self._fetch, by_url))
        failures = [(u, err) for u, _, err in results if err]
        self.stats = {"requests": len(results), "failed": len(failures)}
        if failures and len(failures) == len(results):
            raise RuntimeError(f"all {len(results)} news requests failed, e.g. {failures[0][1][:120]}")
        if failures:
            log.warning("news: %d/%d requests failed, e.g. %s", len(failures), len(results), failures[0][1][:120])

        posts, seen_titles, seen_links = [], set(), set()
        # local feeds first so a story keeps its local outlet's attribution
        for url, d, _ in sorted(results, key=lambda x: by_url[x[0]]["engine"] != "feed"):
            r = by_url[url]
            for e in d.entries:
                when = _when(e)
                if when < ctx.since:
                    continue
                link = e.get("link", "") or e.get("id", "")
                if r["engine"] == "bing":
                    link = bing_target(link)
                tk = title_key(e.get("title", ""))
                if link in seen_links or (tk and tk in seen_titles):
                    continue
                seen_links.add(link)
                seen_titles.add(tk)
                if r["engine"] == "feed":
                    outlet, rel = r["name"], r["reliability"]
                else:
                    outlet = ((e.get("source") or {}).get("title", "") if r["engine"] == "google"
                              else e.get("news_source", "")) or urlparse(link).netloc.replace("www.", "")
                    rel = "B" if ESTABLISHED.search(outlet) or ESTABLISHED.search(link) else "C"
                via = {"google": "Google News RSS", "bing": "Bing News RSS"}.get(r["engine"], f'{r.get("name", "")} RSS feed')
                posts.append(Post(
                    source="news", source_name=outlet, native_id=link, url=link,
                    text=_clean(e.get("title", "") + ". " + e.get("summary", "")),
                    created_at=when, reliability=rel, is_local=r["local"], engagement={"via": via}))
        return posts
