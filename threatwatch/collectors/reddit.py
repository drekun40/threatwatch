"""Reddit via the official API (PRAW). Requires an approved app under Reddit's Responsible
Builder Policy: REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USER_AGENT in .env."""
from __future__ import annotations

from datetime import datetime, timezone

from ..config import env
from ..models import Post
from . import CollectContext, NotConfigured


class RedditCollector:
    name = "reddit"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def _client(self):
        import praw  # optional dependency
        cid, secret = env("REDDIT_CLIENT_ID"), env("REDDIT_CLIENT_SECRET")
        if not cid or not secret:
            raise NotConfigured("REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET not set in .env")
        return praw.Reddit(client_id=cid, client_secret=secret, check_for_async=False,
                           user_agent=env("REDDIT_USER_AGENT", "ThreatWatch/0.1"))

    @staticmethod
    def _post(s, local: bool) -> Post:
        return Post(
            source="reddit", source_name=f"r/{s.subreddit.display_name}", native_id=s.id,
            url=f"https://www.reddit.com{s.permalink}",
            text=f"{s.title}. {getattr(s, 'selftext', '') or ''}"[:4000],
            created_at=datetime.fromtimestamp(s.created_utc, tz=timezone.utc),
            author=str(s.author) if s.author else "[deleted]", reliability="D", is_local=local,
            engagement={"score": s.score, "comments": s.num_comments})

    def collect(self, ctx: CollectContext) -> list[Post]:
        reddit = self._client()
        limit = int(self.cfg.get("per_query_limit", 50))
        subs = self.cfg.get("subreddits", [])
        posts = []

        for sub in subs:     # everything new in local subreddits; matcher decides relevance
            for s in reddit.subreddit(sub).new(limit=limit):
                p = self._post(s, local=True)
                if p.created_at >= ctx.since:
                    posts.append(p)

        for fac in ctx.facilities.get("facilities", []):   # site-wide facility search
            terms = ctx.facility_search_terms(fac, n=3)
            if not terms:
                continue
            q = " OR ".join(f'"{t}"' for t in terms)
            for s in reddit.subreddit("all").search(q, sort="new", time_filter="day", limit=limit):
                if s.subreddit.display_name in subs:
                    continue
                p = self._post(s, local=False)
                if p.created_at >= ctx.since:
                    posts.append(p)
        return posts
