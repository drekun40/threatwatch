"""Turn a match into a scored, tiered hit with an Admiralty-style rating.

Score (0–100) is built from:
  severity        highest category weight x 6                      (0–60)
  breadth         +5 per additional threat category                (max +10)
  context         +5 if a context term (concert, waterfront...) co-occurs
  facility        +10 priority-1 site, +5 priority-2, 0 otherwise, -5 area-only
  source          A +10, B +5, C 0, D -5, E/F -10
  corroboration   +10 per independent source reporting the same facility/category
                  inside the corroboration window                (max +20)
  recency         +5 if the post is under 3 hours old
  event day       +5 if a scheduled event at that venue is within ±6 h (Ticketmaster)

  dampener        -15 if the wording reads as past, legal or non-live coverage (config/filters.yaml)
  score = clamp(sum of the above, 0, 100)

Tiers (thresholds in config/sources.yaml `tiers:`; see tier_for):
  ACT     score >= act (85) AND a monitored site AND (corroborated by 1+ independent source
          OR source reliability in act_reliability, default A/B). Highest urgency; sent like ALERT.
  ALERT   score >= alert (70), monitored site. Sent through the alert channels.
  WATCH   score >= watch (40). Analyst review queue.
  LOG     everything else.
  Items in Buffalo but not at a listed site are capped: LOG if the top category weight is below 9,
  otherwise WATCH at most (never ALERT/ACT).
Admiralty credibility: 2 = 2+ independent corroborating sources, 3 = one, 4 = none,
1 is reserved for analyst confirmation in the dashboard.
"""
from __future__ import annotations

from .matcher import AREA_GENERAL, Matcher
from .models import Hit, Match, Post, utcnow

SOURCE_POINTS = {"A": 10, "B": 5, "C": 0, "D": -5, "E": -10, "F": -10}


def tier_for(score: int, fid: str, top_weight: int, reliability: str, corroborating: int,
             tiers: dict) -> tuple[str, str]:
    """Pure tier decision. Returns (tier, note); note explains a cap or the ACT condition ('' if none)."""
    act, alert, watch = int(tiers.get("act", 85)), int(tiers.get("alert", 70)), int(tiers.get("watch", 40))
    if fid == AREA_GENERAL:
        if top_weight < 9:
            return "LOG", "Capped at Logged: no monitored site and category weight below 9"
        if score >= watch:
            return "WATCH", "Capped at Watch: no monitored site named" if score >= alert else ""
        return "LOG", ""
    if score >= act:
        trusted = reliability in tiers.get("act_reliability", ["A", "B"])
        if corroborating >= 1 or trusted:
            why = "corroborated" if corroborating >= 1 else f"source reliability {reliability}"
            return "ACT", f"Act now: score {score} >= {act} and {why}"
        return "ALERT", f"Not Act: score {score} >= {act} but single low-reliability source"
    if score >= alert:
        return "ALERT", ""
    if score >= watch:
        return "WATCH", ""
    return "LOG", ""


def score_match(post: Post, match: Match, fid: str, matcher: Matcher,
                corroborating: int, tiers: dict, event_day: bool = False) -> Hit:
    """Priority score 0-100 (how urgently to review — not a probability) plus the factors behind it."""
    cats = sorted(match.threat_terms, key=matcher.weight, reverse=True)
    top_weight = matcher.weight(cats[0]) if cats else 0
    f: list[tuple[str, int]] = []

    if cats:
        f.append((f"Severity: {matcher.label(cats[0])} (weight {top_weight}) x 6", top_weight * 6))
    if len(cats) > 1:
        f.append((f"{len(cats) - 1} more threat categor{'y' if len(cats) == 2 else 'ies'} matched", min(10, 5 * (len(cats) - 1))))
    if match.context_terms:
        f.append((f"Context term present: {', '.join(match.context_terms[:3])}", 5))
    if fid == AREA_GENERAL:
        f.append(("Buffalo area, not tied to a monitored site", -5))
    else:
        prio = int(matcher.facilities.get(fid, {}).get("priority", 3))
        pts = {1: 10, 2: 5}.get(prio, 0)
        if pts:
            f.append((f"Site priority {prio}", pts))
    src_pts = SOURCE_POINTS.get(post.reliability, -5)
    if src_pts:
        f.append((f"Source reliability {post.reliability}", src_pts))
    if corroborating:
        f.append((f"{corroborating} other independent source(s) reporting the same site and category", min(20, 10 * corroborating)))
    if event_day:
        f.append(("Scheduled event at this venue within 6 hours", int(tiers.get("event_bonus", 5))))
    if getattr(match, "dampeners", None):
        f.append((f"Reads as past, legal or non-live coverage: {', '.join(match.dampeners[:3])}",
                  -int(getattr(matcher, "dampener_penalty", 15))))
    age_h = (utcnow() - post.created_at).total_seconds() / 3600
    if age_h < 3:
        f.append(("Reported less than 3 hours ago", 5))

    score = max(0, min(100, sum(p for _, p in f)))
    tier, note = tier_for(score, fid, top_weight, post.reliability, corroborating, tiers)
    if note:
        f.append((note, 0))

    cred = 2 if corroborating >= 2 else 3 if corroborating == 1 else 4
    terms = sorted({t for c in cats for t in match.threat_terms[c]}, key=str.lower)
    return Hit(post=post, facility_id=fid, categories=cats, terms=terms, score=score,
               tier=tier, admiralty=f"{post.reliability}{cred}",
               corroborating_sources=corroborating, factors=f)
