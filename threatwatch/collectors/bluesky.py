"""Bluesky public post search (AT Protocol). Free.

Without credentials it searches through Bluesky's public AppView (api.bsky.app), which needs no account.
With BLUESKY_HANDLE + BLUESKY_APP_PASSWORD in .env it searches as that account instead, which has
higher rate limits. Either way it only reads public posts."""
from __future__ import annotations

from datetime import datetime, timezone

import requests

from .. import http

from ..config import env
from ..models import Post, parse_iso
from . import CollectContext

PDS = "https://bsky.social/xrpc"
PUBLIC = "https://api.bsky.app/xrpc"


class BlueskyCollector:
    name = "bluesky"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "ThreatWatch/0.3 (facility security monitoring)"
        self.base = PUBLIC

    def _login(self) -> None:
        handle, pw = env("BLUESKY_HANDLE"), env("BLUESKY_APP_PASSWORD")
        if not handle or not pw:
            self.base = PUBLIC          # no account: public search, no login
            return
        self.base = PDS
        r = http.post(f"{PDS}/com.atproto.server.createSession", session=self.session,
                              json={"identifier": handle, "password": pw}, timeout=20)
        r.raise_for_status()
        self.session.headers["Authorization"] = f"Bearer {r.json()['accessJwt']}"

    def _search(self, q: str, since: datetime) -> list[dict]:
        r = http.get(f"{self.base}/app.bsky.feed.searchPosts", session=self.session, timeout=20, params={
            "q": q, "sort": "latest", "lang": "en",
            "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "limit": int(self.cfg.get("per_query_limit", 50))})
        r.raise_for_status()
        return r.json().get("posts", [])

    def collect(self, ctx: CollectContext) -> list[Post]:
        self._login()
        queries = []
        for fac in ctx.facilities.get("facilities", []):
            queries += [f'"{t}"' for t in ctx.facility_search_terms(fac, n=2)]
        # area-wide sweep: high-severity terms + Buffalo
        queries += [f'"{t}" Buffalo' for t in ctx.high_severity_terms(min_weight=9)]

        posts, seen = [], set()
        for q in queries:
            for item in self._search(q, ctx.since):
                uri = item.get("uri")
                if uri in seen:
                    continue
                seen.add(uri)
                rec = item.get("record", {})
                author = item.get("author", {}).get("handle", "")
                rkey = uri.rsplit("/", 1)[-1]
                when = parse_iso(rec["createdAt"]) \
                    if rec.get("createdAt") else datetime.now(timezone.utc)
                posts.append(Post(
                    source="bluesky", source_name="Bluesky", native_id=uri,
                    url=f"https://bsky.app/profile/{author}/post/{rkey}", text=rec.get("text", ""),
                    created_at=when.astimezone(timezone.utc), author=author, reliability="D",
                    engagement={"likes": item.get("likeCount", 0), "reposts": item.get("repostCount", 0),
                                "replies": item.get("replyCount", 0)}))
        return posts
