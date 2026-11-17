"""ThreatWatch command line.

  python run.py selftest             live check of every source: connects, counts items, explains failures
  python run.py scan                 run one scan (collect, score, alert, export)
  python run.py scan --no-alerts     scan without sending Teams/email
  python run.py scan --auto          hourly mode: full scans at 07/15, extra scans around events and after alerts
  python run.py report [--days 7]    build the weekly executive briefing + analyst report
  python run.py rescore [--days 7]   re-apply current keywords/filters to unreviewed items
  python run.py test-alert           send a test message through every alert channel
  python run.py telegram-login       one-time Telegram login (creates data/telegram.session)
  python run.py demo                 build demo data for the dashboard (data/demo.db)
"""
from __future__ import annotations

import argparse
import logging
import sys
import time

from threatwatch.config import env, load_sources

OK, WARN, FAIL = "\033[32m✓\033[0m", "\033[33m–\033[0m", "\033[31m✗\033[0m"

HINTS = {
    "news": "Check internet access; if one outlet fails, update its feed URL in config/sources.yaml.",
    "nws": "api.weather.gov needs no key; check internet/firewall.",
    "gdelt": "api.gdeltproject.org needs no key; it rate-limits to ~1 query per 5 s — retry later if it refuses.",
    "tfr": "tfr.faa.gov needs no key. Zero items is normal: it only lists restrictions over the Buffalo area.",
    "mastodon": "mastodon.social needs no key; check internet access or change instances in sources.yaml.",
    "bluesky": "Create an app password: Bluesky > Settings > Privacy and security > App passwords.",
    "opendata": "data.buffalony.gov needs no key. Zero items is normal if nothing happened inside a geofence.",
    "ny511": "Register for a free key at 511ny.org/developers and set NY511_API_KEY.",
    "schedules": "Uses free NHL and ESPN feeds; check internet access. Your own events go in config/events.yaml.",
    "events": "Free key at developer.ticketmaster.com (Discovery API) -> TICKETMASTER_API_KEY.",
    "telegram": "Set TELEGRAM_API_ID/HASH (my.telegram.org), run `python run.py telegram-login`, list channels.",
    "youtube": "Google Cloud console > enable 'YouTube Data API v3' > create API key -> YOUTUBE_API_KEY.",
    "adsb": "No key needed; adsb.lol / airplanes.live may rate-limit — retry later.",
    "ais": "Free key at aisstream.io (sign in with GitHub) -> AISSTREAM_API_KEY.",
    "reddit": "Needs Reddit API approval; then set REDDIT_CLIENT_ID/SECRET and enable in sources.yaml.",
    "x": "Pay-per-use: X_BEARER_TOKEN, then enable in sources.yaml.",
}


def cmd_selftest(args):
    """Runs each enabled collector against a throwaway database and reports what happened."""
    import tempfile
    from pathlib import Path

    from threatwatch.collectors import CollectContext, NotConfigured, get_collectors
    from threatwatch.config import load_facilities, load_keywords
    from threatwatch.matcher import Matcher
    from threatwatch.store import Store, window_start

    sources = load_sources()
    if args.source:
        for k, v in sources["sources"].items():
            v["enabled"] = k in args.source
    tmp = Store(Path(tempfile.mkdtemp()) / "selftest.db")
    facs, kws = load_facilities(), load_keywords()
    matcher = Matcher(facs, kws)
    ctx = CollectContext(facs, kws, sources, tmp, window_start(72))
    print("ThreatWatch source self-test (last 72 h, nothing is saved or alerted)\n")
    for c in get_collectors(sources):
        t0 = time.monotonic()
        try:
            posts = c.collect(ctx)
            hits = sum(1 for p in posts if matcher.match(p).is_hit)
            extra = ""
            if c.name == "events":
                extra = f", {tmp.get_state('events_last_count', 0)} events stored"
            if c.name == "gatherings":
                extra = f", {tmp.get_state('gatherings_last_count', 0)} public gatherings near sites in the next 14 days"
            if c.name == "schedules":
                extra = f", {tmp.get_state('schedules_last_count', 0)} home games/events in the next 14 days"
            if c.name == "news" and getattr(c, "stats", None):
                extra = f" from {c.stats['requests']} searches/feeds ({c.stats['failed']} failed)"
            if c.name in ("adsb", "ais"):
                kind = "aircraft" if c.name == "adsb" else "vessel"
                extra = f", {len(tmp.tracks_since(kind, window_start(1)))} {kind} positions"
            print(f" {OK} {c.name:9} {len(posts):4} items, {hits} would be hits{extra}  ({time.monotonic() - t0:.1f}s)")
            for err in (getattr(c, "errors", None) or [])[:3]:
                print(f"      ! {err}")
            if posts and args.verbose:
                for p in posts[:3]:
                    print(f"      · {p.text[:110]}")
        except NotConfigured as e:
            print(f" {WARN} {c.name:9} not set up: {e}\n      → {HINTS.get(c.name, '')}")
        except Exception as e:
            print(f" {FAIL} {c.name:9} FAILED: {str(e)[:200]}\n      → {HINTS.get(c.name, '')}")
    disabled = [k for k, v in load_sources()["sources"].items() if not v.get("enabled")]
    if disabled:
        print(f"\n Disabled in sources.yaml: {', '.join(disabled)}")
    print(f" Alert channels: {env('ALERT_CHANNELS', 'console')}  (test with: python run.py test-alert)")
    from threatwatch.alerts import summary_enabled
    on, why = summary_enabled()
    print(f" Summary email after each scan: {'on' if on else 'off — ' + why}")


def cmd_scan(args):
    from threatwatch.pipeline import auto_reason, run_scan
    light = False
    if args.auto:
        from threatwatch.store import Store
        from threatwatch.pipeline import light_enabled
        sources = load_sources()
        why = auto_reason(Store(), sources)
        light = not why and light_enabled(sources)
        if not why and not light:
            print(time.strftime("%Y-%m-%d %H:%M"), "auto: no event or open alert, skipping this hour")
            return
        print(time.strftime("%Y-%m-%d %H:%M"), "auto:", why or "light hourly scan (fast sources only)")
        from threatwatch.pipeline import online
        if not online():
            print(time.strftime("%Y-%m-%d %H:%M"), "auto: no internet after 90 s (computer asleep or offline); "
                  "skipping instead of logging an empty scan")
            return
    r = run_scan(send_alerts=not args.no_alerts, light=bool(args.auto and light))
    t = r.tier_counts()
    print(f"Collected {r.collected} items, {r.new_posts} new, {len(r.hits)} hits "
          f"(ACT {t['ACT']}, ALERT {t['ALERT']}, WATCH {t['WATCH']}, LOG {t['LOG']}), "
          f"{r.alerts_sent} alert(s) sent.")
    for k in ("alerts", "summary"):
        if k in r.delivery:
            d = r.delivery[k]
            print(f"  {OK if d['ok'] else FAIL} {d['message']}")
    print("  per source: " + ", ".join(f"{k} {v}" for k, v in r.per_source.items()))
    if r.articles.get("tried"):
        print(f"  full article text: {r.articles['fetched']} of {r.articles['tried']} promising items")
    for p in r.export_paths:
        print("  Excel log:", p)
    for k, v in r.not_configured.items():
        print(f"  – {k} not set up: {v}")
    for k, v in r.warnings.items():
        print(f"  ~ {k}: {v}")
    for k, v in r.errors.items():
        print(f"  ! {k}: {v}")


def cmd_rescore(args):
    from threatwatch.pipeline import rescore
    from threatwatch.store import Store
    r = rescore(Store(), days=args.days)
    print(f"Rescored {r['checked']} unreviewed items from the last {args.days} days: "
          f"{r['changed']} changed level, {r['closed']} closed (no longer match).")


def cmd_report(args):
    from threatwatch.report import build_report
    for kind in (args.kind or ["executive", "analyst"]):
        print(build_report(kind, days=args.days))


def cmd_test_alert(args):
    from threatwatch.alerts import send
    ok, errors = send("ThreatWatch test alert", [{
        "facility": "Test facility", "score": 0, "admiralty": "—", "categories": "Test",
        "terms": "test", "source": "ThreatWatch", "time": "now", "corroborating": 0,
        "text": "If you can read this, alert delivery works.", "url": "https://example.com"}])
    print(f"{ok} channel(s) delivered.", *errors, sep="\n")
    from threatwatch.alerts import EmailNotifier, build_scan_summary, summary_enabled
    from threatwatch.config import load_facilities, load_keywords
    from threatwatch.matcher import Matcher
    from threatwatch.pipeline import ScanResult
    on, why = summary_enabled()
    if not on:
        print(f"Summary email: off ({why}).")
        return
    subject, text, html = build_scan_summary(ScanResult(), Matcher(load_facilities(), load_keywords()))
    try:
        EmailNotifier().send_text("[TEST] " + subject, text, html)
        print(f"Summary email: test sent to {env('ALERT_EMAIL_TO')}.")
    except Exception as e:
        print(f"Summary email failed: {e}")


def cmd_telegram_login(args):
    from threatwatch.collectors.telegram import make_client
    client = make_client()
    client.start()   # prompts for phone number and the code Telegram sends you
    me = client.get_me()
    print(f"Logged in as {getattr(me, 'username', None) or me.id}. Session saved; scans can now read channels.")
    client.disconnect()


def cmd_demo(args):
    from threatwatch.demo import build_demo
    print("Demo data written to", build_demo())


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="ThreatWatch facility threat monitor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("selftest"); t.add_argument("source", nargs="*"); t.add_argument("-v", "--verbose", action="store_true")
    t.set_defaults(f=cmd_selftest)
    s = sub.add_parser("scan"); s.add_argument("--no-alerts", action="store_true")
    s.add_argument("--auto", action="store_true", help="hourly mode: scan at 07/15, around events, or after alerts")
    s.set_defaults(f=cmd_scan)
    r = sub.add_parser("report"); r.add_argument("--days", type=int, default=7)
    r.add_argument("--kind", action="append", choices=["executive", "analyst"], help="default: both")
    r.set_defaults(f=cmd_report)
    rs = sub.add_parser("rescore"); rs.add_argument("--days", type=float, default=7); rs.set_defaults(f=cmd_rescore)
    sub.add_parser("test-alert").set_defaults(f=cmd_test_alert)
    sub.add_parser("telegram-login").set_defaults(f=cmd_telegram_login)
    sub.add_parser("demo").set_defaults(f=cmd_demo)
    sub.add_parser("check").set_defaults(f=cmd_selftest, source=[], verbose=False)   # old name
    args = ap.parse_args()
    if args.cmd == "selftest":
        logging.getLogger().setLevel(logging.WARNING)
    args.f(args)


if __name__ == "__main__":
    sys.exit(main())
