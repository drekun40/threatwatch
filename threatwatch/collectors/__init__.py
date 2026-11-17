"""Source collectors. Each returns a list of Post objects; failures are reported, never fatal."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..store import Store


class NotConfigured(RuntimeError):
    """A source is enabled but its key/setup is missing — reported as a setup gap, not an error."""


@dataclass
class CollectContext:
    facilities: dict
    keywords: dict
    sources: dict
    store: Store
    since: datetime          # only keep posts newer than this

    def facility_search_terms(self, fac: dict, n: int = 4) -> list[str]:
        """The most distinctive aliases for search queries (no street addresses, no hashtags)."""
        out = []
        for a in fac.get("aliases", []):
            if a.startswith("#") or any(ch.isdigit() for ch in a):
                continue
            out.append(a)
        return out[:n]

    def high_severity_terms(self, min_weight: int = 8) -> list[str]:
        terms = []
        for c in self.keywords.get("categories", {}).values():
            if int(c.get("weight", 0)) >= min_weight:
                terms += c.get("terms", [])
        return terms


def get_collectors(sources_cfg: dict):
    from .adsb import ADSBCollector
    from .ais import AISCollector
    from .bluesky import BlueskyCollector
    from .events import EventsCollector
    from .gatherings import GatheringsCollector
    from .gdelt import GDELTCollector
    from .mastodon import MastodonCollector
    from .tfr import TFRCollector
    from .news import NewsCollector
    from .ny511 import NY511Collector
    from .nws import NWSCollector
    from .opendata import OpenDataCollector
    from .reddit import RedditCollector
    from .schedules import SchedulesCollector
    from .telegram import TelegramCollector
    from .x import XCollector
    from .youtube import YouTubeCollector

    registry = {"schedules": SchedulesCollector, "events": EventsCollector,   # first: event-day context before scoring
                "gatherings": GatheringsCollector,
                "news": NewsCollector, "gdelt": GDELTCollector, "nws": NWSCollector, "tfr": TFRCollector,
                "mastodon": MastodonCollector, "bluesky": BlueskyCollector,
                "opendata": OpenDataCollector, "ny511": NY511Collector, "telegram": TelegramCollector,
                "youtube": YouTubeCollector, "adsb": ADSBCollector, "ais": AISCollector,
                "reddit": RedditCollector, "x": XCollector}
    out = []
    for name, cls in registry.items():
        cfg = sources_cfg.get("sources", {}).get(name, {})
        if cfg.get("enabled"):
            out.append(cls(cfg))
    return out
