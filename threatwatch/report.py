"""Word reports.

  build_report(kind, ...)   kind = executive | analyst | facility | selected
  build_weekly_report(...)  the scheduled weekly report (analyst type, all sites, 7 days)

Every report states when it was generated, the period, and which sources were working, and keeps
observation, interpretation and unknowns apart. Scores are described as priority scores, not probabilities.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor

from .models import ALERT_TIERS, PRIORITY_LABEL, REVIEW_TIERS, tier_rank
from .config import REPORTS_DIR, load_facilities, load_keywords, load_sources
from .matcher import AREA_GENERAL, Matcher
from . import intel
from .store import INACTIVE, STATUS_LABEL, Store

LOCAL = ZoneInfo("America/New_York")
TIER_COLOR = {"ACT": "B42318", "ALERT": "C2570C", "WATCH": "093C71", "LOG": "8A8A8A"}
MH_BLUE, MH_GREEN = "093C71", "0F594E"   # Mercyhurst blue and green (mercyhurst.edu)


def _shade(cell, hex_color: str) -> None:
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def _local(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone(LOCAL).strftime("%a %b %d %H:%M")


def _table(doc, headers: list[str], rows: list[list[str]], widths=None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = ""
        run = c.paragraphs[0].add_run(h)
        run.bold = True
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        _shade(c, MH_BLUE)
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = ""
            r = cells[i].paragraphs[0].add_run(str(v))
            r.font.size = Pt(9)
    return t


def build_weekly_report(days: int = 7, end: datetime | None = None, store: Store | None = None) -> str:
    store = store or Store()
    matcher = Matcher(load_facilities(), load_keywords())
    sources_cfg = load_sources()
    end = end or datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    rows = store.hits_between(start, end, min_tier="LOG")

    by_tier = Counter(r["tier"] for r in rows)
    by_fac: dict[str, list] = defaultdict(list)
    for r in rows:
        by_fac[r["facility_id"]].append(r)
    by_cat = Counter(c for r in rows for c in json.loads(r["categories"]))

    doc = Document()
    st = doc.styles["Normal"]
    st.font.name = "Calibri"
    st.font.size = Pt(10.5)
    _brand(doc)

    h = doc.add_heading("ThreatWatch — Weekly Facility Threat Report", level=0)
    h.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p = doc.add_paragraph()
    p.add_run(f"Reporting period: {start.astimezone(LOCAL):%b %d, %Y} – {end.astimezone(LOCAL):%b %d, %Y} "
              f"(ET)").bold = True
    doc.add_paragraph(f"Area: Buffalo / Erie County, NY · {len(matcher.facilities)} monitored facilities · "
                      f"Generated {datetime.now(LOCAL):%b %d, %Y %H:%M} ET")
    doc.add_paragraph("Classification: UNCLASSIFIED // FOR OFFICIAL USE — open-source information only.").italic = True

    # ---- BLUF -------------------------------------------------------------
    doc.add_heading("Bottom line up front", level=1)
    if not rows:
        doc.add_paragraph("No threat-relevant open-source reporting was detected for the monitored "
                          "facilities during this period.")
    else:
        top_facs = sorted(by_fac.items(), key=lambda kv: (-max(r["score"] for r in kv[1]), -len(kv[1])))[:3]
        doc.add_paragraph(
            f"{len(rows)} items were flagged this period: {by_tier.get('ACT', 0)} ACT, {by_tier.get('ALERT', 0)} ALERT, "
            f"{by_tier.get('WATCH', 0)} WATCH and {by_tier.get('LOG', 0)} LOG. "
            f"The highest-priority activity concerned "
            + "; ".join(f"{matcher.facility_name(f)} ({len(v)} item(s), max score {max(r['score'] for r in v)})"
                        for f, v in top_facs) + ".")
        if by_cat:
            doc.add_paragraph("Most frequent threat categories: " + ", ".join(
                f"{matcher.label(c)} ({n})" for c, n in by_cat.most_common(4)) + ".")
    doc.add_paragraph("Analyst assessment: ").add_run(
        "[Add judgment, likelihood and recommended actions here before dissemination.]").italic = True

    # ---- summary by facility ---------------------------------------------
    doc.add_heading("Activity by facility", level=1)
    fac_rows = []
    ordered = [f["id"] for f in load_facilities().get("facilities", [])] + [AREA_GENERAL]
    for fid in ordered:
        items = by_fac.get(fid, [])
        t = Counter(r["tier"] for r in items)
        fac_rows.append([matcher.facility_name(fid), str(len(items)), str(t.get("ACT", 0) + t.get("ALERT", 0)),
                         str(t.get("WATCH", 0)), str(max((r["score"] for r in items), default="—"))])
    _table(doc, ["Facility", "Items", "ACT/ALERT", "WATCH", "Max score"], fac_rows)

    # ---- detail ------------------------------------------------------------
    doc.add_heading("Significant items (ACT, ALERT and WATCH)", level=1)
    sig = [r for r in rows if r["tier"] in REVIEW_TIERS]
    if not sig:
        doc.add_paragraph("None this period.")
    for fid in ordered:
        items = sorted([r for r in sig if r["facility_id"] == fid], key=lambda r: -r["score"])
        if not items:
            continue
        doc.add_heading(matcher.facility_name(fid), level=2)
        for r in items:
            para = doc.add_paragraph()
            tr = para.add_run(f"[{r['tier']}] ")
            tr.bold = True
            tr.font.color.rgb = RGBColor.from_string(TIER_COLOR[r["tier"]])
            para.add_run(f"{_local(r['created_at'])} ET · score {r['score']} · rating {r['admiralty']} · "
                         f"{r['source_name']} ({r['source']})").bold = True
            if r["status"] != "new":
                para.add_run(f" · analyst status: {r['status']}")
            doc.add_paragraph(f"Category: {', '.join(matcher.label(c) for c in json.loads(r['categories']))}"
                              f" — terms: {', '.join(json.loads(r['terms']))}", style="List Bullet")
            doc.add_paragraph(f"Reporting: {(r['text'] or '')[:500]}", style="List Bullet")
            if r["corroborating"]:
                doc.add_paragraph(f"Corroborated by {r['corroborating']} independent source(s).", style="List Bullet")
            if r["analyst_note"]:
                doc.add_paragraph(f"Analyst note: {r['analyst_note']}", style="List Bullet")
            doc.add_paragraph(f"Source: {r['url']}", style="List Bullet")

    # ---- low-level log -----------------------------------------------------
    logs = [r for r in rows if r["tier"] == "LOG"]
    if logs:
        doc.add_heading("Logged items (low confidence / low severity)", level=1)
        _table(doc, ["Time (ET)", "Facility", "Category", "Source", "Score"],
               [[_local(r["created_at"]), matcher.facility_name(r["facility_id"]),
                 ", ".join(matcher.label(c) for c in json.loads(r["categories"])),
                 r["source_name"], str(r["score"])] for r in logs[:60]])
        if len(logs) > 60:
            doc.add_paragraph(f"+{len(logs) - 60} further LOG items in the dashboard export.")

    # ---- events -------------------------------------------------------------
    evs = store.events_between(start, end + timedelta(days=7))
    if evs:
        doc.add_heading("Scheduled events at monitored venues", level=1)
        doc.add_paragraph("Crowd context from Ticketmaster for this period and the coming week. Threat items at a venue "
                          "within six hours of an event receive a score increase.")
        _table(doc, ["Date (ET)", "Event", "Venue", "Site"],
               [[_local(e["start_at"]), e["name"], e["venue"], matcher.facility_name(e["facility_id"])] for e in evs[:40]])

    # ---- collection & method ----------------------------------------------
    doc.add_heading("Collection coverage and gaps", level=1)
    src = sources_cfg.get("sources", {})
    scans = [s for s in store.recent_scans(200) if s["started_at"] >= start.isoformat()]
    unset = {k for s in scans for k in json.loads((s["detail"] if "detail" in s.keys() else None) or "{}").get("not_configured", {})}
    for name, cfg in src.items():
        status = "not active" if not cfg.get("enabled") else "enabled, not yet set up" if name in unset else "active"
        doc.add_paragraph(f"{name}: {status}", style="List Bullet")
    errs = Counter(k for s in scans for k in json.loads(s["errors"] or "{}"))
    doc.add_paragraph(f"{len(scans)} scans ran this period."
                      + (f" Source errors: {', '.join(f'{k} ({v}x)' for k, v in errs.items())}." if errs else ""))

    doc.add_heading("Method", level=1)
    doc.add_paragraph(
        "Posts are collected from the active sources, deduplicated, and matched against facility names, "
        "aliases and a threat keyword list. Each item is scored 0–100 on keyword severity, facility priority, "
        "source reliability, corroboration and recency. Ratings use the Admiralty system: the letter is source "
        "reliability (A official, B established media, C known account, D unverified social) and the number "
        "is credibility (1 analyst-confirmed, 2 corroborated by 2+ sources, 3 by one source, 4 uncorroborated). "
        "Automated scores are triage aids, not assessments — every ACT, ALERT and WATCH item requires analyst review.")

    out = REPORTS_DIR / f"ThreatWatch_weekly_{end.astimezone(LOCAL):%Y-%m-%d}.docx"
    doc.save(out)
    return str(out)


# =============================================================================================== typed reports
SOURCE_REL = {"A": "official record or sensor", "B": "established news outlet", "C": "known or verified account",
              "D": "unverified social media", "E": "doubtful", "F": "cannot be judged"}
CRED = {"1": "confirmed by an analyst", "2": "corroborated by 2+ independent sources",
        "3": "corroborated by 1 independent source", "4": "uncorroborated"}
TITLES = {"executive": "Executive Briefing", "analyst": "Analyst Report", "facility": "Facility Report",
          "selected": "Selected Incidents Report"}


def _brand(doc) -> None:
    """Headings in Mercyhurst blue (title, level 1) and green (level 2)."""
    for name, color in (("Title", MH_BLUE), ("Heading 1", MH_BLUE), ("Heading 2", MH_GREEN)):
        try:
            doc.styles[name].font.color.rgb = RGBColor.from_string(color)
        except KeyError:
            pass


def _doc():
    doc = Document()
    st = doc.styles["Normal"]
    st.font.name = "Calibri"
    st.font.size = Pt(10.5)
    _brand(doc)
    return doc


def _header(doc, kind, start, end, matcher, health, demo, extra=""):
    h = doc.add_heading(f"ThreatWatch — {TITLES[kind]}{extra}", level=0)
    h.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p = doc.add_paragraph()
    p.add_run(f"Period: {start.astimezone(LOCAL):%b %d, %Y %H:%M} – {end.astimezone(LOCAL):%b %d, %Y %H:%M} ET").bold = True
    doc.add_paragraph(f"Generated {datetime.now(LOCAL):%b %d, %Y %H:%M} ET · Buffalo / Erie County, NY · "
                      f"{len(matcher.facilities)} monitored sites")
    working = [x["name"] for x in health if x["enabled"] and x["level"] == "good"]
    gaps = [f"{x['name']} ({x['status'].lower()})" for x in health if x["enabled"] and x["level"] != "good"]
    doc.add_paragraph(f"Data coverage: {intel.coverage_level(health)}. Working: {', '.join(working) or 'none'}."
                      + (f" Gaps: {', '.join(gaps)}." if gaps else ""))
    if demo:
        w = doc.add_paragraph().add_run("DEMO DATA — synthetic examples, not real incidents.")
        w.bold = True
        w.font.color.rgb = RGBColor.from_string("C0392B")
    doc.add_paragraph("UNCLASSIFIED // FOR OFFICIAL USE — open-source information only.").italic = True


def _filter(rows, facility_ids, statuses, categories, hit_ids):
    out = []
    for r in rows:
        if hit_ids is not None and r["id"] not in hit_ids:
            continue
        if hit_ids is None and facility_ids and r["facility_id"] not in facility_ids:
            continue
        if statuses and r["status"] not in statuses:
            continue
        if not statuses and hit_ids is None and r["status"] in INACTIVE:
            continue
        if categories and not set(json.loads(r["categories"])) & set(categories):
            continue
        out.append(r)
    return out


def _incident(doc, store, matcher, r, full=True):
    para = doc.add_paragraph()
    tr = para.add_run(f"[{PRIORITY_LABEL.get(r['tier'], 'Priority 3')}] ")
    tr.bold = True
    tr.font.color.rgb = RGBColor.from_string(TIER_COLOR[r["tier"]])
    para.add_run(f"{matcher.facility_name(r['facility_id'])} — {_local(r['created_at'])} ET").bold = True
    doc.add_paragraph(f"Reported: {(r['text'] or '')[:600]}", style="List Bullet")
    adm = r["admiralty"] or "D4"
    doc.add_paragraph(f"Source: {r['source_name']} ({SOURCE_REL.get(adm[0], adm[0])}). Credibility: "
                      f"{CRED.get(adm[1:], adm[1:])}. Rating {adm}.", style="List Bullet")
    if full:
        h = store.hit(r["id"])
        factors = json.loads(h["factors"] or "[]") if h and "factors" in h.keys() and h["factors"] else []
        why = "; ".join(f"{t} ({'+' if p > 0 else ''}{p})" for t, p in factors) if factors else \
            f"matched {', '.join(json.loads(r['terms']))}"
        doc.add_paragraph(f"Why flagged (priority score {r['score']}/100, not a probability): {why}.", style="List Bullet")
        rel = store.related(r["id"])
        if rel:
            indep = sum(1 for x in rel if not x["same_source"])
            doc.add_paragraph(f"Possibly related reports: {len(rel)} ({indep} from other sources, {len(rel) - indep} "
                              "repeat coverage from the same source).", style="List Bullet")
        if h and h["collected_at"]:
            doc.add_paragraph(f"Collected by ThreatWatch: {_local(h['collected_at'])} ET.", style="List Bullet")
    doc.add_paragraph(f"Analyst status: {STATUS_LABEL.get(r['status'], r['status'])}"
                      + (f" — {r['analyst_note']}" if r["analyst_note"] else "") + ".", style="List Bullet")
    if r["url"]:
        doc.add_paragraph(f"Link: {r['url']}", style="List Bullet")


def build_report(kind: str = "analyst", store: Store | None = None, days: int = 7, facility_ids=None, statuses=None,
                 min_tier: str = "WATCH", categories=None, hit_ids=None, demo: bool = False,
                 end: datetime | None = None) -> str:
    store = store or Store()
    matcher = Matcher(load_facilities(), load_keywords())
    sources_cfg = load_sources()
    end = end or datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    health = intel.data_health(store, sources_cfg, end)
    rows = [dict(r) for r in store.hits_between(start, end + timedelta(minutes=1),
                                                 "LOG" if hit_ids else min_tier, include_dismissed=True)]
    rows = _filter(rows, facility_ids, statuses, categories, set(hit_ids) if hit_ids else None)
    rows.sort(key=lambda r: (tier_rank(r["tier"]), -r["score"]))
    doc = _doc()
    extra = ""
    if kind == "facility" and facility_ids:
        extra = ": " + ", ".join(matcher.facility_name(f).split(" (")[0].split(" —")[0] for f in facility_ids[:3])
    _header(doc, kind, start, end, matcher, health, demo, extra)

    if kind == "executive":
        B = intel.briefing(store, matcher, sources_cfg, end, days)
        doc.add_heading("Bottom line up front", level=1)
        doc.add_paragraph(f"What the data shows: {B['observation']}")
        if B["interpretation"]:
            doc.add_paragraph(f"What it may mean: {B['interpretation']}")
        doc.add_paragraph(f"What we don't know: {B['unknowns']}")
        doc.add_heading("Facilities requiring attention", level=1)
        by = defaultdict(list)
        for r in [x for x in rows if x["status"] in intel.OPEN]:
            by[r["facility_id"]].append(r)
        if by:
            _table(doc, ["Site", "Open items", "Priority 0–1", "Highest item", "Score"],
                   [[matcher.facility_name(f), str(len(v)), str(sum(x["tier"] in ALERT_TIERS for x in v)),
                     (max(v, key=lambda x: x["score"])["text"] or "")[:90], str(max(x["score"] for x in v))]
                    for f, v in sorted(by.items(), key=lambda kv: -max(x["score"] for x in kv[1]))])
        else:
            doc.add_paragraph("No monitored site has open Alert or Watch items.")
        doc.add_heading("Significant changes (last 24 h vs previous 24 h)", level=1)
        if not B["changes"]["enough_history"]:
            doc.add_paragraph("Not enough history to establish a baseline yet; counts are shown for reference only.")
        for lbl, p, c in B["changes"]["rows"]:
            doc.add_paragraph(f"{lbl}: {intel.compare(p, c)}", style="List Bullet")
        for n in B["changes"]["notable"]:
            doc.add_paragraph(f"{n['text']} {n['caveat']}", style="List Bullet")
        doc.add_heading("Key uncertainties", level=1)
        doc.add_paragraph(B["unknowns"])
        for g in B["gaps"]:
            doc.add_paragraph(f"Coverage gap: {g['name']} — {g['status']}. {g['coverage']}", style="List Bullet")
        doc.add_heading("Recommended follow-up", level=1)
        recs = [f"Review {matcher.facility_name(r['facility_id'])}: {(r['text'] or '')[:100]}" for r in B["priority"][:5]]
        single = [r for r in rows if r["tier"] in ALERT_TIERS and not r["corroborating"] and r["status"] in intel.OPEN]
        if single:
            recs.append(f"Seek independent corroboration for {len(single)} single-source Priority 0–1 item(s).")
        recs += [f"Restore or set up the {g['name']} source ({g['status'].lower()})." for g in B["gaps"][:4]]
        for t in recs or ["No follow-up required from the collected data."]:
            doc.add_paragraph(t, style="List Bullet")
        doc.add_paragraph("Analyst judgment: ").add_run("[Add your assessment before sending.]").italic = True

    elif kind == "facility":
        for fid in facility_ids or []:
            S = intel.facility_summary(store, matcher, fid, end)
            obs, interp, unk = intel.facility_narrative(S)
            doc.add_heading(matcher.facility_name(fid), level=1)
            f = matcher.facilities.get(fid, {})
            doc.add_paragraph(f"{f.get('address', '')} · priority {f.get('priority', 3)} · geofence {f.get('radius_km', .5)} km")
            doc.add_paragraph(f"Observation: {obs}")
            doc.add_paragraph(f"Interpretation: {interp}")
            doc.add_paragraph(f"Unknown: {unk}")
            doc.add_heading("Open items", level=2)
            for r in sorted(S["open"], key=lambda r: -r["score"])[:15]:
                _incident(doc, store, matcher, r)
            if not S["open"]:
                doc.add_paragraph("None.")
            doc.add_heading("Upcoming events (14 days)", level=2)
            for e in S["events"]:
                doc.add_paragraph(f"{_local(e['start_at'])} ET — {e['name']} ({e['source']})", style="List Bullet")
            if not S["events"]:
                doc.add_paragraph("None scheduled.")
            doc.add_heading("Review outcomes", level=2)
            doc.add_paragraph(", ".join(f"{k}: {v}" for k, v in S["outcomes"].items()) or "Nothing reviewed yet.")
            if S["nearby"]:
                doc.add_heading("Nearby public-safety context (7 days, within 2 km)", level=2)
                doc.add_paragraph("Context only — proximity does not mean the site was affected.")
                for p in S["nearby"]:
                    doc.add_paragraph(f"{_local(p['created_at'])} ET, {p['km']:.1f} km: {(p['text'] or '')[:140]}",
                                      style="List Bullet")

    else:   # analyst / selected
        doc.add_heading("Summary", level=1)
        by_t = Counter(r["tier"] for r in rows)
        doc.add_paragraph(f"{len(rows)} item(s): {by_t.get('ACT', 0)} Priority 0, {by_t.get('ALERT', 0)} Priority 1, {by_t.get('WATCH', 0)} Priority 2, "
                          f"{by_t.get('LOG', 0)} Priority 3. "
                          f"{sum(1 for r in rows if r['corroborating'])} corroborated by another source; "
                          f"{sum(1 for r in rows if r['status'] == 'confirmed')} confirmed by an analyst.")
        doc.add_heading("Incidents", level=1)
        if not rows:
            doc.add_paragraph("No items match the selected filters.")
        groups = defaultdict(list)
        for r in rows:
            groups[r["facility_id"]].append(r)
        for fid, items in sorted(groups.items(), key=lambda kv: -max(x["score"] for x in kv[1])):
            doc.add_heading(matcher.facility_name(fid), level=2)
            for r in items:
                _incident(doc, store, matcher, r)
        doc.add_heading("Outstanding information gaps", level=1)
        gaps = [x for x in health if x["enabled"] and x["level"] != "good"]
        for g in gaps:
            doc.add_paragraph(f"{g['name']}: {g['status']}. {g['coverage']}", style="List Bullet")
        if not gaps:
            doc.add_paragraph("All enabled sources were working.")
        doc.add_paragraph("Single-source items remain unverified until corroborated or confirmed by review.")
        doc.add_heading("Method", level=1)
        doc.add_paragraph(
            "Items are collected from the listed sources, deduplicated, and matched against site names, aliases, "
            "geofences and a threat keyword list. The priority score (0–100) ranks review urgency from keyword severity, "
            "site priority, source reliability, corroboration, event proximity and recency; it is not a probability. "
            "Ratings: letter = source reliability, number = information credibility.")

    tag = f"_{facility_ids[0]}" if kind == "facility" and facility_ids else ""
    out = REPORTS_DIR / f"ThreatWatch_{kind}_{end.astimezone(LOCAL):%Y-%m-%d_%H%M}{tag}.docx"
    doc.save(out)
    return str(out)
