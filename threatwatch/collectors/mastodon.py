"""Mastodon public hashtag timelines (Buffalo tags). Free, no key, public posts only."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from html import unescape

import requests

from .. import http

from ..models import Post
from . import CollectContext
from .news import UA


def _clean(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html or "")).split())


class MastodonCollector:
    name = "mastodon"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        posts, seen, errors, calls = [], set(), [], 0
        for inst in self.cfg.get("instances", ["mastodon.social"]):
            for tag in self.cfg.get("tags", ["buffalo"]):
                max_id, pages = None, int(self.cfg.get("pages", 2))
                for _ in range(pages):
                    calls += 1
                    params = {"limit": 40}
                    if max_id:
                        params["max_id"] = max_id
                    try:
                        r = http.get(f"https://{inst}/api/v1/timelines/tag/{tag}", params=params,
                                         headers={"User-Agent": UA}, timeout=20)
                        r.raise_for_status()
                        items = r.json()
                    except Exception as e:
                        errors.append(f"{inst} #{tag}: {str(e)[:100]}")
                        break
                    if not items:
                        break
                    oldest = None
                    for s in items:
                        when = datetime.fromisoformat(s["created_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
                        oldest = when
                        if when < ctx.since or s.get("uri") in seen:
                            continue
                        if s.get("language") != "en":   # English only, as for every other source
                            continue
                        seen.add(s.get("uri"))
                        acct = (s.get("account") or {}).get("acct", "")
                        posts.append(Post(
                            source="mastodon", source_name=f"Mastodon #{tag}", native_id=s.get("uri", s["id"]),
                            url=s.get("url") or s.get("uri", ""), text=_clean(s.get("content", "")),
                            created_at=when, author=acct, reliability="D",
                            engagement={"likes": s.get("favourites_count", 0), "reposts": s.get("reblogs_count", 0),
                                        "replies": s.get("replies_count", 0)}))
                    max_id = items[-1]["id"]
                    if oldest and oldest < ctx.since:
                        break
        if errors and len(errors) >= calls:
            raise RuntimeError(errors[0])
        return posts
