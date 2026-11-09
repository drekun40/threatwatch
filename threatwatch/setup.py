"""What each optional source needs, and a one-source live test for the dashboard's setup page."""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from .config import env, load_facilities, load_keywords, load_sources

# source -> setup facts. fields: (ENV_NAME, label, secret)
CONNECT = {
    "bluesky": dict(title="Bluesky", minutes=2, adds="Public posts that name a site, plus threat-term searches.",
                    url="https://bsky.app/settings/app-passwords",
                    steps="Sign in to Bluesky → Settings → Privacy and security → App passwords → Add. "
                          "Use your handle (name.bsky.social) and the app password, not your normal password.",
                    fields=[("BLUESKY_HANDLE", "Handle", False), ("BLUESKY_APP_PASSWORD", "App password", True)]),
    "youtube": dict(title="YouTube", minutes=5, adds="Videos and livestreams near sites and keyword searches.",
                    url="https://console.cloud.google.com/apis/library/youtube.googleapis.com",
                    steps="Google Cloud console → create a project → enable YouTube Data API v3 → Credentials → "
                          "Create credentials → API key.",
                    fields=[("YOUTUBE_API_KEY", "API key", True)]),
    "events": dict(title="Ticketmaster", minutes=3, adds="Concerts and shows at venues; items near an event score higher.",
                   url="https://developer-acct.ticketmaster.com/user/register",
                   steps="Register → My Apps → copy the Consumer Key.",
                   fields=[("TICKETMASTER_API_KEY", "Consumer key", True)]),
    "ny511": dict(title="511NY traffic", minutes=3, adds="Crashes, closures and police activity near sites.",
                  url="https://511ny.org/developers/help",
                  steps="Register for a developer key; it arrives by email.",
                  fields=[("NY511_API_KEY", "API key", True)]),
    "ais": dict(title="AIS vessels", minutes=2, adds="Vessels on the waterfront: aground, stopped at the rail bridge, speeding.",
                url="https://aisstream.io/authenticate",
                steps="Sign in with GitHub → API Keys → Create.",
                fields=[("AISSTREAM_API_KEY", "API key", True)]),
    "telegram": dict(title="Telegram", minutes=5, adds="Public channels you choose (read-only).",
                     url="https://my.telegram.org/apps",
                     steps="my.telegram.org → API development tools → create an app. Then run "
                           "`python run.py telegram-login` once in Terminal and list channels below.",
                     fields=[("TELEGRAM_API_ID", "API ID", False), ("TELEGRAM_API_HASH", "API hash", True)]),
    "opendata": dict(title="Open Data Buffalo token", minutes=2, adds="Optional: higher rate limits for police data.",
                     url="https://data.buffalony.gov/profile/edit/developer_settings",
                     steps="Sign in → Developer settings → Create new app token.",
                     fields=[("SOCRATA_APP_TOKEN", "App token", True)]),
    "reddit": dict(title="Reddit", minutes=0, adds="Local subreddits. Needs Reddit's approval first.",
                   url="https://www.reddit.com/prefs/apps",
                   steps="Request API access under Reddit's Responsible Builder Policy. Once approved, create a script app "
                         "and add its ID and secret, then switch Reddit on below.",
                   fields=[("REDDIT_CLIENT_ID", "Client ID", False), ("REDDIT_CLIENT_SECRET", "Client secret", True)]),
    "x": dict(title="X", minutes=0, adds="Posts naming sites. Pay-per-use (about $5 per 1,000 posts read).",
              url="https://developer.x.com/en/portal/dashboard",
              steps="Developer portal → create a project → copy the Bearer token. The monthly read cap in "
                    "sources.yaml limits spend.",
              fields=[("X_BEARER_TOKEN", "Bearer token", True)]),
}

EMAIL_FIELDS = [("SMTP_HOST", "SMTP server", False), ("SMTP_PORT", "Port", False), ("SMTP_USER", "Username", False),
                ("SMTP_PASSWORD", "Password / app password", True), ("ALERT_EMAIL_TO", "Send to", False)]


def is_connected(name: str) -> bool:
    c = CONNECT.get(name)
    return bool(c) and all(env(k) for k, _, _ in c["fields"])


def check_source(name: str) -> dict:
    """Run one collector against a throwaway database. Nothing is saved or alerted."""
    from .collectors import CollectContext, NotConfigured, get_collectors
    from .matcher import Matcher
    from .store import Store, window_start

    sources = load_sources()
    cfg = sources["sources"].get(name, {})
    one = {"sources": {name: {**cfg, "enabled": True}}}
    tmp = Store(Path(tempfile.mkdtemp()) / "check.db")
    facs, kws = load_facilities(), load_keywords()
    ctx = CollectContext(facs, kws, sources, tmp, window_start(72))
    t0 = time.monotonic()
    try:
        c = get_collectors(one)[0]
        posts = c.collect(ctx)
        m = Matcher(facs, kws)
        hits = sum(1 for p in posts if m.match(p).is_hit)
        return {"ok": True, "items": len(posts), "hits": hits, "seconds": round(time.monotonic() - t0, 1),
                "message": f"Working: {len(posts)} items in the last 72 h, {hits} would be flagged.",
                "sample": [p.text[:120] for p in posts[:3]]}
    except NotConfigured as e:
        return {"ok": False, "message": f"Not set up: {e}"}
    except Exception as e:
        return {"ok": False, "message": f"Failed: {str(e)[:240]}"}
