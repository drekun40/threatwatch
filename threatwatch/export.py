"""Excel log of important items (Alert and Watch), rebuilt after every scan and every review save.

One workbook, same columns every time: exports/ThreatWatch_alerts.xlsx
  Sheet "Alerts & Watch"  every Alert/Watch item in the database, newest first, with clickable source links
  Sheet "Latest scan"     only the Alert/Watch items found by the most recent scan
  Sheet "Upcoming events" scheduled events at monitored sites for the next 14 days
  Sheet "Scan log"        one row per scan
Logged (low-level) items are left out on purpose. Dismissed items stay in the log with status "dismissed"
so the record is complete; filter the Status column to hide them.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from .config import EXPORTS_DIR
from .matcher import Matcher

ET = ZoneInfo("America/New_York")
XLSX = EXPORTS_DIR / "ThreatWatch_alerts.xlsx"

COLUMNS = [  # (header, width)
    ("Reported (ET)", 17), ("Detected (ET)", 17), ("Level", 8), ("Score", 7), ("Rating", 7),
    ("Site", 30), ("Site priority", 8), ("Category", 28), ("Matched terms", 26), ("Source", 24),
    ("Source type", 11), ("Summary", 70), ("Link", 12), ("Corroborated by", 10), ("Event nearby", 30),
    ("Status", 11), ("Analyst note", 30), ("Item ID", 8),
]
HEADER_FILL = PatternFill("solid", fgColor="1D1D1F")
LEVEL_FILL = {"ACT": PatternFill("solid", fgColor="F6D3D0"), "ALERT": PatternFill("solid", fgColor="FDE2D7"),
              "WATCH": PatternFill("solid", fgColor="E6E6E6")}
LEVEL_WORD = {"ACT": "Act now", "ALERT": "Alert", "WATCH": "Watch"}
WORD_LEVEL = {v: k for k, v in LEVEL_WORD.items()}


def _et(iso: str | None) -> str:
    if not iso:
        return ""
    return datetime.fromisoformat(iso).astimezone(ET).strftime("%Y-%m-%d %H:%M")


def _sheet(wb, title: str, headers: list[tuple[str, int]], first: bool = False):
    ws = wb.active if first else wb.create_sheet()
    ws.title = title
    ws.append([h for h, _ in headers])
    for i, (_, w) in enumerate(headers, 1):
        c = ws.cell(row=1, column=i)
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = HEADER_FILL
        c.alignment = Alignment(vertical="center", wrap_text=True)
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = "A2"
    ws.row_dimensions[1].height = 30
    return ws


def _hit_rows(store, matcher: Matcher, rows) -> list[list]:
    out = []
    for r in rows:
        f = matcher.facilities.get(r["facility_id"], {})
        ev = store.event_near(r["facility_id"], datetime.fromisoformat(r["created_at"])) if f else None
        out.append([
            _et(r["created_at"]), _et(r["detected_at"]), LEVEL_WORD.get(r["tier"], r["tier"]), r["score"],
            r["admiralty"], matcher.facility_name(r["facility_id"]), f.get("priority", ""),
            ", ".join(matcher.label(c) for c in json.loads(r["categories"])), ", ".join(json.loads(r["terms"])),
            r["source_name"], r["source"], (r["text"] or "")[:1000], r["url"] or "", r["corroborating"],
            f'{ev["name"]} ({_et(ev["start_at"])})' if ev else "", r["status"], r["analyst_note"] or "", r["id"]])
    return out


def _write_hits(ws, data: list[list]) -> None:
    link_col = [h for h, _ in COLUMNS].index("Link") + 1
    for row in data:
        ws.append(row)
        rnum = ws.max_row
        level = WORD_LEVEL.get(row[2], "WATCH")
        for col in range(1, len(COLUMNS) + 1):
            cell = ws.cell(row=rnum, column=col)
            cell.alignment = Alignment(vertical="top", wrap_text=col in (8, 9, 12, 15, 17))
        ws.cell(row=rnum, column=3).fill = LEVEL_FILL[level]
        url = row[link_col - 1]
        lc = ws.cell(row=rnum, column=link_col)
        if url.startswith("http"):
            lc.value = "Open source"
            lc.hyperlink = url
            lc.font = Font(color="0563C1", underline="single")
        else:
            lc.value = "no link"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}{max(ws.max_row, 2)}"


def write_excel(store, matcher: Matcher, latest_hit_ids: list[int] | None = None) -> str:
    """Rebuild the workbook from the database. Returns the path written."""
    now = datetime.now(timezone.utc)
    rows = store.hits_between(now - timedelta(days=3650), now + timedelta(days=1), min_tier="WATCH",
                              include_dismissed=True)
    wb = Workbook()
    ws = _sheet(wb, "Alerts & Watch", COLUMNS, first=True)
    _write_hits(ws, _hit_rows(store, matcher, rows))

    ws2 = _sheet(wb, "Latest scan", COLUMNS)
    if latest_hit_ids is None:   # e.g. after a review save: keep the previous scan's ids
        latest_hit_ids = store.get_state("excel_latest_ids", [])
    store.set_state("excel_latest_ids", latest_hit_ids)
    latest = [r for r in rows if r["id"] in set(latest_hit_ids)]
    _write_hits(ws2, _hit_rows(store, matcher, latest))
    if not latest:
        ws2.append(["No new Alert or Watch items in the latest scan."])

    ws3 = _sheet(wb, "Upcoming events", [("Date (ET)", 17), ("Event", 44), ("Venue", 30), ("Site", 30),
                                         ("Source", 14), ("Link", 12)])
    for e in store.events_between(now - timedelta(hours=6), now + timedelta(days=14)):
        ws3.append([_et(e["start_at"]), e["name"], e["venue"], matcher.facility_name(e["facility_id"]),
                    e["source"], "Open" if (e["url"] or "").startswith("http") else ""])
        if (e["url"] or "").startswith("http"):
            c = ws3.cell(row=ws3.max_row, column=6)
            c.hyperlink, c.font = e["url"], Font(color="0563C1", underline="single")

    ws4 = _sheet(wb, "Scan log", [("Finished (ET)", 17), ("Collected", 10), ("New", 8), ("Flagged", 9),
                                  ("Alerts sent", 10), ("Errors", 60)])
    for s in store.recent_scans(500):
        errs = json.loads(s["errors"] or "{}")
        ws4.append([_et(s["finished_at"]), s["collected"], s["new_posts"], s["hits"], s["alerts"],
                    "; ".join(f"{k}: {v[:80]}" for k, v in errs.items())])

    try:
        wb.save(XLSX)
        return str(XLSX)
    except PermissionError:   # file open and locked (Windows Excel): write a timestamped copy instead
        alt = EXPORTS_DIR / f"ThreatWatch_alerts_{now.astimezone(ET):%Y%m%d_%H%M}.xlsx"
        wb.save(alt)
        return str(alt)


# ------------------------------------------------------------------ collection log workbook
COLLECTION_XLSX = EXPORTS_DIR / "ThreatWatch_collection_log.xlsx"
SOURCE_COLUMNS = [
    ("Scan ID", 8), ("Scan finished (ET)", 18), ("Source", 12), ("Status", 14), ("Items returned", 10),
    ("New", 8), ("Flagged", 9), ("Seconds", 9), ("Problem", 60),
]
STATE_WORD = {"ok": "Working", "empty": "No new items", "error": "Not reachable", "not_configured": "Not set up"}
LEVEL_FILL_TEMPLATE = {"High": PatternFill("solid", fgColor="FDE2D7"), "Moderate": PatternFill("solid", fgColor="EDEDED")}


def write_collection_excel(store, days: int = 30) -> str:
    """Collection log in the analyst template (every item, logged once when first collected) plus one row
    per source per scan. Rebuilt after each scan and after notes are edited on the dashboard."""
    from .collection import EXTRA_COLUMNS, TEMPLATE_COLUMNS, analyst_initials, template_row
    now = datetime.now(timezone.utc)
    items = store.collection(since=now - timedelta(days=days), limit=200000)
    cols = TEMPLATE_COLUMNS + EXTRA_COLUMNS
    wb = Workbook()
    ws = _sheet(wb, "Collection log", cols, first=True)
    ws.row_dimensions[1].height = 42
    url_col, lvl_col = 6, 11
    who = analyst_initials()
    for r in items:
        row = template_row(r, who)
        ws.append(row)
        n = ws.max_row
        for col in range(1, len(cols) + 1):
            ws.cell(row=n, column=col).alignment = Alignment(vertical="top", wrap_text=col in (9, 10))
        if str(row[url_col - 1]).startswith("http"):
            c = ws.cell(row=n, column=url_col)
            c.hyperlink = row[url_col - 1]
            c.font = Font(color="0563C1", underline="single")
        if row[lvl_col - 1] in LEVEL_FILL_TEMPLATE:
            ws.cell(row=n, column=lvl_col).fill = LEVEL_FILL_TEMPLATE[row[lvl_col - 1]]
    for i in range(len(TEMPLATE_COLUMNS) + 1, len(cols) + 1):   # extras after the template, in gray
        ws.cell(row=1, column=i).fill = PatternFill("solid", fgColor="8A8A8A")
    ws.auto_filter.ref = f"A1:{get_column_letter(len(cols))}{max(ws.max_row, 2)}"

    ws2 = _sheet(wb, "Sources per scan", SOURCE_COLUMNS)
    for sc in store.logged_scans(400):
        if sc["finished_at"] and sc["finished_at"] < (now - timedelta(days=days)).isoformat():
            break
        for s in store.scan_sources(sc["id"]):
            ws2.append([sc["id"], _et(sc["finished_at"]), s["source"], STATE_WORD.get(s["state"], s["state"]),
                        s["items"], s["new"], s["flagged"], s["seconds"], s["error"] or ""])
    ws2.auto_filter.ref = f"A1:{get_column_letter(len(SOURCE_COLUMNS))}{max(ws2.max_row, 2)}"
    try:
        wb.save(COLLECTION_XLSX)
        return str(COLLECTION_XLSX)
    except PermissionError:   # open in Excel: save next to it instead of failing the scan
        alt = COLLECTION_XLSX.with_name(f"ThreatWatch_collection_log_{now:%Y%m%d_%H%M}.xlsx")
        wb.save(alt)
        return str(alt)
