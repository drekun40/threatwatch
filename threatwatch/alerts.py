"""Alert delivery. Notifiers are pluggable: add a class with send(subject, items) and register it.

Configured from .env:
  ALERT_CHANNELS=mac,email          (any of: mac, teams, email, console; mac = Notification Center banner)
  TEAMS_WEBHOOK_URL=...             (Teams Workflows "When a Teams webhook request is received")
  SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASSWORD / ALERT_EMAIL_FROM / ALERT_EMAIL_TO
  SCAN_SUMMARY_EMAIL=1              (default 1: email a summary after every scan when "email" is a channel)

Two kinds of message:
  - alerts: ACT and ALERT items, sent once each through every channel (dispatch_alerts)
  - scan summary: one email after every scan, even when nothing was found (send_scan_summary)
"""
from __future__ import annotations

import json
import smtplib
from email.message import EmailMessage
from html import escape

import requests

from .config import env
from .matcher import Matcher


def _items(rows, matcher: Matcher) -> list[dict]:
    out = []
    for r in rows:
        cats = json.loads(r["categories"])
        out.append({
            "id": r["id"], "facility": matcher.facility_name(r["facility_id"]),
            "score": r["score"], "admiralty": r["admiralty"],
            "categories": ", ".join(matcher.label(c) for c in cats),
            "terms": ", ".join(json.loads(r["terms"])),
            "source": f'{r["source_name"]} ({r["source"]})', "time": r["created_at"][:16].replace("T", " ") + "Z",
            "text": (r["text"] or "")[:400], "url": r["url"],
            "corroborating": r["corroborating"]})
    return out


class ConsoleNotifier:
    def send(self, subject: str, items: list[dict]) -> None:
        print(f"\n=== {subject} ===")
        for i in items:
            print(f"[{i['score']}] {i['facility']} | {i['categories']} | {i['admiralty']} | {i['url']}")


class MacNotifier:
    """A macOS Notification Center banner per alert batch. No setup: works on the Mac that runs the scans.
    The banner names the top item; the dashboard and Excel log have the rest."""

    def __init__(self):
        import sys
        if sys.platform != "darwin":
            raise RuntimeError("the mac channel only works on macOS")

    @staticmethod
    def _q(text: str) -> str:   # AppleScript string literal
        return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'

    def send(self, subject: str, items: list[dict]) -> None:
        import subprocess
        top = items[0] if items else {}
        more = f" (+{len(items) - 1} more)" if len(items) > 1 else ""
        body = f"[{top.get('score', '')}] {top.get('facility', '')}: {top.get('categories', '')}{more}" if top else subject
        script = (f"display notification {self._q(body[:220])} with title \"ThreatWatch\" "
                  f"subtitle {self._q(subject[:120])} sound name \"Submarine\"")
        subprocess.run(["osascript", "-e", script], check=True, capture_output=True, timeout=15)


class TeamsNotifier:
    """Posts an Adaptive Card to a Teams Workflows webhook (the replacement for O365 connectors)."""

    def __init__(self):
        self.url = env("TEAMS_WEBHOOK_URL")
        if not self.url:
            raise RuntimeError("TEAMS_WEBHOOK_URL not set")

    def send(self, subject: str, items: list[dict]) -> None:
        body = [{"type": "TextBlock", "text": subject, "weight": "Bolder", "size": "Large",
                 "color": "Attention", "wrap": True}]
        for i in items[:10]:
            body += [
                {"type": "TextBlock", "text": f"**{i['facility']}** — score {i['score']} · {i['admiralty']}",
                 "wrap": True, "spacing": "Medium", "separator": True},
                {"type": "FactSet", "facts": [
                    {"title": "Category", "value": i["categories"]},
                    {"title": "Terms", "value": i["terms"]},
                    {"title": "Source", "value": i["source"]},
                    {"title": "Time", "value": i["time"]},
                    {"title": "Corroborated by", "value": f"{i['corroborating']} other source(s)"}]},
                {"type": "TextBlock", "text": i["text"], "wrap": True, "isSubtle": True},
                {"type": "TextBlock", "text": f"[Open source]({i['url']})", "wrap": True},
            ]
        if len(items) > 10:
            body.append({"type": "TextBlock", "text": f"+{len(items) - 10} more in the dashboard"})
        card = {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4", "body": body}}]}
        r = requests.post(self.url, json=card, timeout=20)
        r.raise_for_status()


class EmailNotifier:
    def __init__(self):
        self.host = env("SMTP_HOST")
        self.to = env("ALERT_EMAIL_TO")
        if not self.host or not self.to:
            raise RuntimeError("SMTP_HOST / ALERT_EMAIL_TO not set")

    def send(self, subject: str, items: list[dict]) -> None:
        lines = [subject, ""]
        for i in items:
            lines += [f"{i['facility']}  —  score {i['score']}  ({i['admiralty']})",
                      f"  Category: {i['categories']}   Terms: {i['terms']}",
                      f"  Source: {i['source']}   Time: {i['time']}   Corroborated by: {i['corroborating']}",
                      f"  {i['text']}", f"  {i['url']}", ""]
        self.send_text(subject, "\n".join(lines))

    def send_text(self, subject: str, text: str, html: str | None = None,
                  attachments: list[tuple[str, bytes, str]] | None = None) -> None:
        """attachments: (filename, data, mime type 'type/subtype')."""
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = env("ALERT_EMAIL_FROM", env("SMTP_USER", "threatwatch@localhost"))
        msg["To"] = self.to
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")
        for name, data, mime in attachments or []:
            maintype, subtype = mime.split("/", 1)
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
        port = int(env("SMTP_PORT", "587"))
        with smtplib.SMTP(self.host, port, timeout=30) as s:
            if port != 25:
                s.starttls()
            if env("SMTP_USER"):
                s.login(env("SMTP_USER"), env("SMTP_PASSWORD", ""))
            s.send_message(msg)


NOTIFIERS = {"console": ConsoleNotifier, "mac": MacNotifier, "teams": TeamsNotifier, "email": EmailNotifier}


def get_notifiers() -> list:
    names = [n.strip() for n in env("ALERT_CHANNELS", "console").split(",") if n.strip()]
    return [NOTIFIERS[n]() for n in names if n in NOTIFIERS]


def send(subject: str, items: list[dict]) -> tuple[int, list[str]]:
    """Send through every configured channel. Returns (channels that succeeded, errors)."""
    ok, errors = 0, []
    try:
        notifiers = get_notifiers()
    except Exception as e:
        return 0, [str(e)]
    for n in notifiers:
        try:
            n.send(subject, items)
            ok += 1
        except Exception as e:
            errors.append(f"{type(n).__name__}: {e}")
    return ok, errors


def channels() -> list[str]:
    return [n.strip() for n in (env("ALERT_CHANNELS", "console") or "").split(",") if n.strip()]


def dispatch_alerts(store, matcher: Matcher) -> int:
    """Send ACT and ALERT items that haven't been sent yet. Returns how many were sent."""
    rows = store.pending_alerts()
    if not rows:
        return 0
    items = _items(rows, matcher)
    facs = sorted({i["facility"] for i in items})
    acts = sum(r["tier"] == "ACT" for r in rows)
    label = f"ACT NOW ({acts}) + ALERT" if acts else "ALERT"
    subject = f"ThreatWatch {label} — {len(items)} item(s): {', '.join(facs)[:150]}"
    ok, errors = send(subject, items)
    if ok:   # delivered somewhere: don't resend next scan
        store.mark_alerted([r["id"] for r in rows])
    if errors:
        raise RuntimeError("; ".join(errors))
    return len(rows)


# ------------------------------------------------------------------ scan summary email
def summary_enabled() -> tuple[bool, str]:
    """(will send, reason if not)."""
    if (env("SCAN_SUMMARY_EMAIL", "1") or "1").strip().lower() in ("0", "false", "no", "off"):
        return False, "turned off (SCAN_SUMMARY_EMAIL=0)"
    if "email" not in channels():
        return False, "email is not in ALERT_CHANNELS"
    if not env("SMTP_HOST") or not env("ALERT_EMAIL_TO"):
        return False, "SMTP_HOST / ALERT_EMAIL_TO not set"
    return True, ""


def build_scan_summary(result, matcher: Matcher, max_items: int = 10) -> tuple[str, str, str]:
    """(subject, plain text, html) for one scan. Pure: no network, easy to test."""
    from .models import REVIEW_TIERS, TIER_WORD, tier_rank
    tiers = {t: 0 for t in ("ACT", "ALERT", "WATCH", "LOG")}
    for h in result.hits:
        tiers[h.tier] = tiers.get(h.tier, 0) + 1
    alerts = tiers["ACT"] + tiers["ALERT"]
    subject = (f"ThreatWatch scan — {result.new_posts} new, {alerts} alert{'s' if alerts != 1 else ''}, "
               f"{tiers['WATCH']} watch{'es' if tiers['WATCH'] != 1 else ''}"
               + (f" ({tiers['ACT']} ACT NOW)" if tiers["ACT"] else ""))
    top = sorted([h for h in result.hits if h.tier in REVIEW_TIERS],
                 key=lambda h: (tier_rank(h.tier), -h.score))[:max_items]
    src = ", ".join(f"{k} {v}" for k, v in sorted(result.per_source.items())) or "none"
    per = source_table(result)

    t = [subject, "",
         f"Collected {result.collected} items, {result.new_posts} new.",
         f"Flagged: {tiers['ACT']} Act now, {tiers['ALERT']} Alert, {tiers['WATCH']} Watch, {tiers['LOG']} Logged.",
         f"Alert messages sent: {result.alerts_sent}.", "", "Collection by source (items / new / flagged):"]
    t += [f"  {r['source']:<10} {r['state_word']:<14} {r['items']:>4} / {r['new']:>3} / {r['flagged']:>2}" for r in per]
    if result.errors:
        t += ["", "Errors:"] + [f"  - {k}: {v}" for k, v in result.errors.items()]
    if result.not_configured:
        t += ["", "Not set up: " + ", ".join(sorted(result.not_configured))]
    t += ["", "Top items:" if top else "No Alert or Watch items this scan."]
    for h in top:
        t += [f"  [{TIER_WORD[h.tier]} · {h.score} · {h.admiralty}] {matcher.facility_name(h.facility_id)}",
              f"    {(h.post.text or '')[:220]}", f"    {h.post.url or 'no link'}"]
    t += ["", "Scores rank items for review; they are not probabilities. Open the dashboard to review."]

    color = {"ACT": "#B42318", "ALERT": "#C2570C", "WATCH": "#093C71"}   # same as the dashboard
    rows = "".join(
        f'<tr><td style="padding:8px 10px;border-top:1px solid #eee"><span style="color:{color[h.tier]};font-weight:600">'
        f'{TIER_WORD[h.tier]}</span><br><span style="color:#6e6e73">{h.score} · {escape(h.admiralty)}</span></td>'
        f'<td style="padding:8px 10px;border-top:1px solid #eee"><b>{escape(matcher.facility_name(h.facility_id))}</b><br>'
        f'{escape((h.post.text or "")[:220])}<br>'
        + (f'<a href="{escape(h.post.url)}">Open source</a>' if (h.post.url or "").startswith("http") else
           '<span style="color:#6e6e73">no link</span>') + '</td></tr>' for h in top)
    issues = "".join(f"<li><b>{escape(k)}</b>: {escape(str(v))}</li>" for k, v in result.errors.items())
    html = (f'<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;color:#1d1d1f;max-width:680px">'
            f'<h2 style="margin:0 0 4px">{escape(subject)}</h2>'
            f'<p style="color:#6e6e73;margin:0 0 14px">Collected {result.collected} · new {result.new_posts} · '
            f'Act now {tiers["ACT"]} · Alert {tiers["ALERT"]} · Watch {tiers["WATCH"]} · Logged {tiers["LOG"]} · '
            f'alert messages sent {result.alerts_sent}</p>'
            + (f'<table style="border-collapse:collapse;width:100%;font-size:14px">{rows}</table>' if top else
               '<p>No Alert or Watch items this scan.</p>')
            + ('<table style="border-collapse:collapse;font-size:12px;margin-top:16px;color:#1d1d1f">'
               '<tr style="color:#6e6e73"><td style="padding:3px 10px 3px 0">Source</td><td style="padding:3px 10px">Status</td>'
               '<td style="padding:3px 10px;text-align:right">Items</td><td style="padding:3px 10px;text-align:right">New</td>'
               '<td style="padding:3px 10px;text-align:right">Flagged</td></tr>'
               + "".join(f'<tr><td style="padding:3px 10px 3px 0;border-top:1px solid #eee">{escape(r["source"])}</td>'
                         f'<td style="padding:3px 10px;border-top:1px solid #eee">{escape(r["state_word"])}</td>'
                         f'<td style="padding:3px 10px;border-top:1px solid #eee;text-align:right">{r["items"]}</td>'
                         f'<td style="padding:3px 10px;border-top:1px solid #eee;text-align:right">{r["new"]}</td>'
                         f'<td style="padding:3px 10px;border-top:1px solid #eee;text-align:right">{r["flagged"]}</td></tr>'
                         for r in per) + "</table>" if per else
               f'<p style="color:#6e6e73;font-size:12px;margin-top:16px">Per source: {escape(src)}</p>')
            + ('<p style="color:#6e6e73;font-size:12px">Attached: this scan\'s full collection log (CSV).</p>'
               if result.collection else "")
            + (f'<p style="font-size:13px"><b>Errors</b></p><ul style="font-size:13px">{issues}</ul>' if issues else "")
            + (f'<p style="color:#6e6e73;font-size:12px">Not set up: {escape(", ".join(sorted(result.not_configured)))}</p>'
               if result.not_configured else "")
            + '<p style="color:#6e6e73;font-size:12px">Scores rank items for review; they are not probabilities.</p></div>')
    return subject, "\n".join(t), html


def source_table(result) -> list[dict]:
    """One row per source for this scan: status, items, new, flagged."""
    words = {"ok": "Working", "empty": "No new items", "error": "Not reachable", "not_configured": "Not set up"}
    counts = {}
    for r in getattr(result, "collection", []) or []:
        d = counts.setdefault(r["source"], [0, 0, 0])
        d[0] += 1
        d[1] += r["outcome"] == "new"
        d[2] += bool(r["level"])
    out = []
    for name, d in (getattr(result, "source_detail", {}) or {}).items():
        c = counts.get(name, [0, 0, 0])
        out.append({"source": name, "state": d["state"], "state_word": words.get(d["state"], d["state"]),
                    "items": c[0], "new": c[1], "flagged": c[2]})
    order = {"error": 0, "ok": 1, "empty": 2, "not_configured": 3}
    return sorted(out, key=lambda r: (order.get(r["state"], 9), -r["items"], r["source"]))


def collection_csv(result) -> bytes:
    """This scan's newly collected items in the analyst collection-log template."""
    import csv
    import io

    from .collection import headers, template_row
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(headers())
    for r in result.collection:
        if r["outcome"] == "new":
            w.writerow(template_row({**r, "scan_id": result.scan_id or ""}))
    return buf.getvalue().encode("utf-8-sig")   # BOM so Excel opens it as UTF-8


def send_scan_summary(result, matcher: Matcher) -> tuple[bool, str]:
    """Email the scan summary if enabled. Returns (sent, message). Never raises."""
    ok, why = summary_enabled()
    if not ok:
        return False, f"summary email skipped: {why}"
    try:
        subject, text, html = build_scan_summary(result, matcher)
        att = []
        if getattr(result, "collection", None):
            from datetime import datetime
            att = [(f"ThreatWatch_collection_scan{result.scan_id or ''}_{datetime.now():%Y%m%d_%H%M}.csv",
                    collection_csv(result), "text/csv")]
        EmailNotifier().send_text(subject, text, html, att)
        return True, f"summary email sent to {env('ALERT_EMAIL_TO')}"
    except Exception as e:
        return False, f"summary email failed: {e}"
