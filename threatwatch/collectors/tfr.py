"""FAA Temporary Flight Restrictions over the Buffalo area (VIP visits, security, hazards). Free, no key.

A new security or VIP TFR over Buffalo means a protected visit or an incident: high-value context
for every downtown site. The standing stadium TFR for NFL games is not listed here (it is permanent).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import requests

from .. import http

from ..models import Post
from . import CollectContext
from .news import UA

LIST = "https://tfr.faa.gov/tfrapi/exportTfrList"
AREA = re.compile(r"\b(BUFFALO|ORCHARD PARK|NIAGARA FALLS|CHEEKTOWAGA|AMHERST|LACKAWANNA|WEST SENECA|"
                  r"HAMBURG|TONAWANDA|LOCKPORT|GETZVILLE|ERIE COUNTY|LAKE ERIE)\b", re.I)


class TFRCollector:
    name = "tfr"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        r = http.get(LIST, headers={"User-Agent": UA}, timeout=30)
        r.raise_for_status()
        posts = []
        for t in r.json():
            desc = t.get("description", "")
            if t.get("state") != "NY" or not AREA.search(desc):
                continue
            nid = t.get("notam_id", "")
            try:
                when = datetime.strptime(t.get("creation_date", ""), "%m/%d/%Y").replace(tzinfo=timezone.utc)
            except Exception:
                when = datetime.now(timezone.utc)
            kind = (t.get("type") or "").title()
            posts.append(Post(
                source="tfr", source_name="FAA TFR", native_id=nid,
                url=f"https://tfr.faa.gov/tfr3/?page=detail_{nid.replace('/', '_')}",
                text=f"FAA temporary flight restriction ({kind}) NOTAM {nid}: {desc}. "
                     f"Flight restriction in effect over the Buffalo area.",
                created_at=max(when, ctx.since), reliability="A", is_local=True))
        return posts
