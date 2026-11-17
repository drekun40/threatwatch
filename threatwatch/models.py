"""Common data shapes passed between collectors, matcher, scoring and storage."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone


TIERS = ("ACT", "ALERT", "WATCH", "LOG")      # highest first
ALERT_TIERS = ("ACT", "ALERT")               # sent through alert channels
REVIEW_TIERS = ("ACT", "ALERT", "WATCH")     # go to the analyst queue, Excel log and reports


PRIORITY_LABEL = {"ACT": "Priority 0 · Act now", "ALERT": "Priority 1", "WATCH": "Priority 2", "LOG": "Priority 3"}
TIER_WORD = {"ACT": "Act now", "ALERT": "Alert", "WATCH": "Watch", "LOG": "Logged"}


def tier_rank(tier: str) -> int:
    """0 for ACT (most urgent) … 3 for LOG; unknown tiers sort last."""
    return TIERS.index(tier) if tier in TIERS else len(TIERS)


def tiers_at_or_above(tier: str) -> tuple[str, ...]:
    return TIERS[:TIERS.index(tier) + 1]


@dataclass
class Post:
    source: str               # "news", "nws", "bluesky", "reddit", "x"
    source_name: str          # outlet / subreddit / platform display name
    native_id: str            # platform's own id (or url for news)
    url: str
    text: str
    created_at: datetime      # always timezone-aware UTC
    author: str = ""
    reliability: str = "D"    # Admiralty source reliability A–F
    is_local: bool = False    # came from a Buffalo-specific source (local subreddit, local outlet, NWS zone)
    engagement: dict = field(default_factory=dict)
    lat: float | None = None
    lon: float | None = None
    body: str = ""            # lead paragraphs of the article, when fetched (threatwatch/article.py)

    @property
    def uid(self) -> str:
        return hashlib.sha1(f"{self.source}:{self.native_id}".encode()).hexdigest()[:16]

    @property
    def text_fingerprint(self) -> str:
        """Used to collapse reposts / syndicated copies of the same story."""
        norm = " ".join(self.text.lower().split())[:200]
        return hashlib.sha1(norm.encode()).hexdigest()[:16]


@dataclass
class Match:
    facilities: list[str]                 # facility ids
    threat_terms: dict[str, list[str]]    # category -> matched terms (weight > 0 only)
    context_terms: list[str]
    area_only: bool = False               # matched Buffalo but no specific facility
    dampeners: list = field(default_factory=list)   # wording that suggests past/legal/non-live coverage
    proximity: dict = field(default_factory=dict)   # site -> nearby street/intersection that placed it there
    body_sites: list = field(default_factory=list)       # sites found only in the article text, not the headline
    body_categories: list = field(default_factory=list)  # threat categories found only in the article text

    @property
    def is_hit(self) -> bool:
        return bool(self.facilities) and bool(self.threat_terms)


@dataclass
class Hit:
    post: Post
    facility_id: str
    categories: list[str]
    terms: list[str]
    score: int
    tier: str                 # "ACT" | "ALERT" | "WATCH" | "LOG"
    admiralty: str            # e.g. "B3"
    corroborating_sources: int = 0
    factors: list = field(default_factory=list)   # [(explanation, points), ...] behind the score


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


_FRACTION = re.compile(r"\.(\d+)")


def parse_iso(value: str) -> datetime:
    """ISO 8601 from an API, as aware UTC. Python 3.10's fromisoformat rejects a trailing "Z" and more than
    fractions that aren't 3 or 6 digits (Bluesky sends nanoseconds: 2026-11-09T01:02:57.899061308+00:00).
    A value without a zone is taken as UTC."""
    s = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], str(value).strip().replace("Z", "+00:00"))
    when = datetime.fromisoformat(s)
    return (when if when.tzinfo else when.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
