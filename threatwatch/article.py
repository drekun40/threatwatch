"""Full article text for promising new items (scan.article_text in config/sources.yaml).

Search results and feeds give a headline plus a one-line summary, so a site named in paragraph four
is missed. Before matching, new items that are local or already mention Buffalo with a threat term get
their article fetched once and the lead paragraphs kept in Post.body, which the matcher reads with the
headline. The headline (Post.text) is what the dashboard and logs show; body is stored for rescoring.

Polite by design: robots.txt is honoured for our user agent, Google News redirect links are skipped
(they don't lead to the article), domains that throttle us can be listed under skip_domains, and at most
`max_per_scan` articles are fetched, in parallel, each with a short timeout.
"""
from __future__ import annotations

import html
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

from . import http
from .matcher import Matcher
from .models import Post

log = logging.getLogger("threatwatch")
UA = "ThreatWatch/0.3 (facility security monitoring; reads public news articles)"
ARTICLE_SOURCES = {"news", "gdelt"}
_DROP = re.compile(r"<(script|style|noscript|nav|header|footer|aside|form|figure|svg)\b.*?</\1>", re.S | re.I)
_PARA = re.compile(r"<p\b[^>]*>(.*?)</p>", re.S | re.I)
_TAG = re.compile(r"<[^>]+>")
_robots: dict[str, RobotFileParser | None] = {}


def extract_text(page: str, max_chars: int = 3000) -> str:
    """The article's lead paragraphs: <p> text outside navigation, footers and asides, short lines
    (bylines, captions, buttons) dropped. Capped so sidebar teasers further down don't leak in."""
    page = _DROP.sub(" ", page)
    out, size = [], 0
    for raw in _PARA.findall(page):
        text = " ".join(html.unescape(_TAG.sub(" ", raw)).split())
        if len(text) < 60:
            continue
        out.append(text)
        size += len(text)
        if size >= max_chars:
            break
    return " ".join(out)[:max_chars]


def allowed(url: str) -> bool:
    """robots.txt for our user agent; an unreadable robots.txt counts as allowed (the usual convention)."""
    host = urlparse(url)
    root = f"{host.scheme}://{host.netloc}"
    if root not in _robots:
        try:
            r = http.get(f"{root}/robots.txt", headers={"User-Agent": UA}, timeout=8, tries=1)
            if r.status_code >= 400:
                _robots[root] = None
            else:
                rp = RobotFileParser()
                rp.parse(r.text.splitlines())
                _robots[root] = rp
        except Exception:
            _robots[root] = None
    rp = _robots[root]
    return rp is None or rp.can_fetch(UA, url)


def fetch_body(url: str, timeout: float = 10, max_chars: int = 3000) -> str:
    if not allowed(url):
        return ""
    r = http.get(url, headers={"User-Agent": UA}, timeout=timeout, tries=1)
    if r.status_code >= 400 or "html" not in r.headers.get("content-type", "html"):
        return ""
    return extract_text(r.text[:2_000_000], max_chars)


def candidates(posts: list[Post], matcher: Matcher, skip_domains: list[str]) -> list[Post]:
    """New-looking news items worth reading in full, most useful first:
    1. Buffalo-area threat items not tied to a site (the article may name the site or a street),
    2. local outlet stories with no threat term in the headline (the article may have one),
    3. items already at a site (the article can add categories)."""
    ranked = []
    for p in posts:
        host = urlparse(p.url or "").netloc.lower()
        if p.source not in ARTICLE_SOURCES or not p.url.startswith("http") or p.body:
            continue
        if "news.google.com" in host or any(host == d or host.endswith("." + d) for d in skip_domains):
            continue
        m = matcher.match(p)
        if m.threat_terms and m.area_only:
            ranked.append((0, p))
        elif p.is_local and not m.threat_terms:
            ranked.append((1, p))
        elif m.is_hit:
            ranked.append((2, p))
    return [p for _, p in sorted(ranked, key=lambda x: x[0])]


def enrich(posts: list[Post], matcher: Matcher, cfg: dict, is_new) -> dict:
    """Fill Post.body for the best candidates among `posts` that `is_new(post)` says aren't stored yet.
    Returns counts for the scan report. Never raises: a failed article is simply left as a headline."""
    if not cfg.get("enabled", True):
        return {"fetched": 0, "tried": 0}
    pool = candidates([p for p in posts if is_new(p)], matcher, list(cfg.get("skip_domains", [])))
    pool = pool[:int(cfg.get("max_per_scan", 40))]
    timeout, max_chars = float(cfg.get("timeout", 10)), int(cfg.get("max_chars", 3000))

    def one(p: Post):
        try:
            return p, fetch_body(p.url, timeout, max_chars)
        except Exception as e:
            log.debug("article %s: %s", p.url, e)
            return p, ""

    fetched = 0
    with ThreadPoolExecutor(max_workers=int(cfg.get("parallel", 6))) as ex:
        for p, body in ex.map(one, pool):
            if body:
                p.body = body
                fetched += 1
    return {"fetched": fetched, "tried": len(pool)}
