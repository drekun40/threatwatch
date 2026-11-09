"""X (Twitter) API v2 recent search — pay-per-use. Needs X_BEARER_TOKEN in .env.

Cost control:
  * since_id per query is stored, so each post is only paid for once.
  * monthly_read_cap in sources.yaml is a hard stop; the counter resets each calendar month.
"""
from __future__ import annotations

from datetime import datetime, timezone

import requests

from .. import http

from ..config import env
from ..models import Post, parse_iso
from . import CollectContext, NotConfigured

URL = "https://api.x.com/2/tweets/search/recent"


class XCollector:
    name = "x"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def _queries(self, ctx: CollectContext) -> dict[str, str]:
        qs = {}
        for fac in ctx.facilities.get("facilities", []):
            terms = ctx.facility_search_terms(fac, n=4)
            if terms:
                qs[f"fac:{fac['id']}"] = "(" + " OR ".join(f'"{t}"' for t in terms) + ") -is:retweet lang:en"
            if self.cfg.get("use_geo") and fac.get("lat") is not None:
                r = min(float(fac.get("radius_km", 0.5)), 40)
                qs[f"geo:{fac['id']}"] = (f"point_radius:[{fac['lon']} {fac['lat']} {r}km] "
                                          "-is:retweet")
        return qs

    def collect(self, ctx: CollectContext) -> list[Post]:
        token = env("X_BEARER_TOKEN")
        if not token:
            raise NotConfigured("X_BEARER_TOKEN not set in .env")
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        usage = ctx.store.get_state("x_usage", {})
        used = usage.get(month, 0)
        cap = int(self.cfg.get("monthly_read_cap", 30000))
        since_ids = ctx.store.get_state("x_since_ids", {})
        headers = {"Authorization": f"Bearer {token}"}
        posts = []

        for key, q in self._queries(ctx).items():
            if used >= cap:
                raise RuntimeError(f"X monthly read cap reached ({used}/{cap}) — skipping remaining queries")
            params = {"query": q, "max_results": 100,
                      "tweet.fields": "created_at,public_metrics,geo,author_id,lang",
                      "expansions": "author_id", "user.fields": "username,verified"}
            if since_ids.get(key):
                params["since_id"] = since_ids[key]
            else:
                params["start_time"] = ctx.since.strftime("%Y-%m-%dT%H:%M:%SZ")
            r = http.get(URL, headers=headers, params=params, timeout=30)
            if r.status_code == 400 and key.startswith("geo:"):
                continue   # geo operators not available on this access level
            r.raise_for_status()
            body = r.json()
            data = body.get("data", [])
            users = {u["id"]: u for u in body.get("includes", {}).get("users", [])}
            used += len(data)
            if body.get("meta", {}).get("newest_id"):
                since_ids[key] = body["meta"]["newest_id"]
            for t in data:
                u = users.get(t.get("author_id"), {})
                handle = u.get("username", "")
                posts.append(Post(
                    source="x", source_name="X", native_id=t["id"],
                    url=f"https://x.com/{handle or 'i'}/status/{t['id']}", text=t.get("text", ""),
                    created_at=parse_iso(t["created_at"]),
                    author=handle, reliability="C" if u.get("verified") else "D",
                    is_local=key.startswith("geo:"), engagement=t.get("public_metrics", {})))

        usage[month] = used
        ctx.store.set_state("x_usage", usage)
        ctx.store.set_state("x_since_ids", since_ids)
        return posts
