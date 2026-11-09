"""ThreatWatch dashboard — run with:  streamlit run app.py"""
from __future__ import annotations

import html
import json
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from pathlib import Path

import altair as alt
import pandas as pd
import pydeck as pdk
import streamlit as st

from threatwatch.config import (DATA_DIR, FACILITIES_FILE, FACILITIES_HEADER, KEYWORDS_FILE,
                                KEYWORDS_HEADER, load_facilities, load_keywords, load_sources, save_yaml)
from threatwatch.matcher import AREA_GENERAL, Matcher
from threatwatch import intel
from threatwatch.models import ALERT_TIERS, PRIORITY_LABEL, REVIEW_TIERS, TIER_WORD, tier_rank
from threatwatch.store import INACTIVE, OPEN, STATUS_LABEL, STATUSES, Store

st.set_page_config(page_title="ThreatWatch", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
ET = ZoneInfo("America/New_York")

# ------------------------------------------------------------------ appearance (light / dark)
# Card-dashboard palette (gray canvas, white cards, black primary, orange accent), light and dark. The choice is saved in data/ui.json and also applied
# to Streamlit's own theme, so native widgets (tables, dropdowns, dialogs) switch with the custom styling.
PALETTES = {
    # Warm-neutral card dashboard: gray canvas, white cards, black primary, orange accent.
    "light": dict(LABEL="#141414", SECONDARY="#737373", SEPARATOR="#EBEBEB", CANVAS="#F1F1F1", SURFACE="#FFFFFF",
                  FILL="#F4F4F4", SELECTED="#141414", TRACK="#F0F0F0", HAIR="rgba(0,0,0,.05)", SHADOW="rgba(0,0,0,.06)",
                  SIDEBAR="#FFFFFF", GLASS="rgba(255,255,255,.90)", MAP_BG="#E9EDF0",
                  DOT_RING="rgba(255,255,255,.55)", TOOLTIP_BG="rgba(255,255,255,.97)",
                  LIVE_BG="#E7F6EC", LIVE_FG="#15803D", DEMO_BG="#FFF1E8", DEMO_FG="#C2410C", DEMO_TEXT="#9A3412",
                  INK="#141414", ON_INK="#FFFFFF", ACCENT="#F2622E", ACCENT_2="#FF8A5B", ACCENT_SOFT="#FDEDE6",
                  UP_BG="#FDECEC", UP_FG="#D92D20", DOWN_BG="#E7F6EC", DOWN_FG="#15803D",
                  RED="#E5484D", ORANGE="#F2622E", BLUE="#2563EB", GRAY="#A3A3A3", GREEN="#16A34A",
                  PURPLE="#9B5DE5", CYAN="#0EA5E9", INDIGO="#4F46E5", YELLOW="#EAB308", ACT_RED="#B42318",
                  WATCH="#2B2B2B", LOG_GRAY="#B5B5B5", CHART_LOG="#D9D9D9"),
    "dark": dict(LABEL="#F4F4F5", SECONDARY="#A1A1AA", SEPARATOR="#2A2A2E", CANVAS="#0C0C0E", SURFACE="#18181B",
                 FILL="#232327", SELECTED="#F4F4F5", TRACK="#26262A", HAIR="rgba(255,255,255,.06)", SHADOW="rgba(0,0,0,.45)",
                 SIDEBAR="#141416", GLASS="rgba(24,24,27,.92)", MAP_BG="#1B1F23",
                 DOT_RING="rgba(0,0,0,.35)", TOOLTIP_BG="rgba(35,35,39,.97)",
                 LIVE_BG="rgba(34,197,94,.14)", LIVE_FG="#4ADE80", DEMO_BG="rgba(242,98,46,.16)", DEMO_FG="#FF8A5B",
                 DEMO_TEXT="#FFB693",
                 INK="#F4F4F5", ON_INK="#141414", ACCENT="#F2622E", ACCENT_2="#FF8A5B", ACCENT_SOFT="rgba(242,98,46,.16)",
                 UP_BG="rgba(229,72,77,.16)", UP_FG="#FF6B6F", DOWN_BG="rgba(34,197,94,.14)", DOWN_FG="#4ADE80",
                 RED="#FF6B6F", ORANGE="#FF7A45", BLUE="#60A5FA", GRAY="#52525B", GREEN="#4ADE80",
                 PURPLE="#C084FC", CYAN="#38BDF8", INDIGO="#818CF8", YELLOW="#FACC15", ACT_RED="#E0312B",
                 WATCH="#D4D4D8", LOG_GRAY="#71717A", CHART_LOG="#3F3F46"),
}
UI_FILE = DATA_DIR / "ui.json"


def load_ui() -> dict:
    try:
        return json.loads(UI_FILE.read_text())
    except Exception:
        return {}


def save_ui(**kw) -> None:
    try:
        UI_FILE.parent.mkdir(parents=True, exist_ok=True)
        UI_FILE.write_text(json.dumps({**load_ui(), **kw}))
    except OSError:
        pass   # a read-only folder just means the choice isn't remembered


def apply_streamlit_theme(name: str) -> bool:
    """Point Streamlit's own theme at the palette. Returns True if it changed (the page then reruns)."""
    from streamlit import config as st_config
    p = PALETTES[name]
    want = {"base": name, "primaryColor": p["ACCENT"], "backgroundColor": p["CANVAS"],
            "secondaryBackgroundColor": p["SURFACE"], "textColor": p["LABEL"]}
    changed = False
    for k, v in want.items():
        if st_config.get_option(f"theme.{k}") != v:
            st_config.set_option(f"theme.{k}", v, "<appearance>")
            changed = True
    return changed


def _on_appearance() -> None:
    if st.session_state.get("appearance") in ("Light", "Dark"):
        save_ui(appearance=st.session_state["appearance"])


if st.session_state.get("appearance") not in ("Light", "Dark"):   # first load, or the selected option clicked off
    saved = load_ui().get("appearance")
    st.session_state["appearance"] = saved if saved in ("Light", "Dark") else "Light"
THEME = "dark" if st.session_state["appearance"] == "Dark" else "light"
if apply_streamlit_theme(THEME):
    st.rerun()   # the next run carries the new theme to the browser
P = PALETTES[THEME]
LABEL, SECONDARY, SEPARATOR, CANVAS, SURFACE = P["LABEL"], P["SECONDARY"], P["SEPARATOR"], P["CANVAS"], P["SURFACE"]
RED, ORANGE, BLUE, GRAY, GREEN = P["RED"], P["ORANGE"], P["BLUE"], P["GRAY"], P["GREEN"]
PURPLE, CYAN, INDIGO, YELLOW = P["PURPLE"], P["CYAN"], P["INDIGO"], P["YELLOW"]
ACT_RED = P["ACT_RED"]     # deeper than system red: Act now outranks Alert
ACCENT, INK = P["ACCENT"], P["INK"]
STATUS = {"ACT": ACT_RED, "ALERT": ACCENT, "WATCH": P["WATCH"], "LOG": P["LOG_GRAY"], "NONE": SECONDARY}
STATUS_WORD = {**TIER_WORD, "NONE": "Quiet"}


def rgb(hex_: str, a: int = 255) -> list[int]:
    return [int(hex_[i:i + 2], 16) for i in (1, 3, 5)] + [a]


FONT = '"Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", "Helvetica Neue", sans-serif'

CSS = f"""
<style>
  @import url("https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap");
  html, body, .stApp, .stApp * :not(.material-symbols-rounded):not([data-testid="stIconMaterial"]) {{
      font-family:{FONT}; }}
  .stApp {{ background:{CANVAS}; color:{LABEL}; }}
  .block-container {{ padding-top:1.4rem; padding-bottom:3rem; max-width:1520px; }}
  header[data-testid="stHeader"] {{ background:transparent; }}
  .num {{ font-variant-numeric:tabular-nums; }}

  /* sidebar: a white panel */
  [data-testid="stSidebar"] {{ background:{P["SIDEBAR"]}; border-right:1px solid {SEPARATOR}; }}
  [data-testid="stSidebar"] h3 {{ font-size:12px; font-weight:600; color:{SECONDARY}; margin:16px 0 4px;
      text-transform:uppercase; letter-spacing:.06em; }}
  .brand {{ display:flex; align-items:center; gap:10px; font-size:18px; font-weight:800; letter-spacing:-.3px; margin-bottom:6px; }}
  .brand-sub {{ font-size:11px; font-weight:500; color:{SECONDARY}; letter-spacing:0; margin-top:-1px; }}
  [class*="st-key-sb_"] {{ background:{P["FILL"]}; border-radius:18px; padding:12px 12px 10px; gap:.35rem; }}
  [class*="st-key-sb_"] [data-testid="stWidgetLabel"] p {{ font-size:10.5px; font-weight:700; color:{SECONDARY};
      letter-spacing:.05em; text-transform:uppercase; }}
  .sb-label {{ font-size:10.5px; font-weight:700; color:{SECONDARY}; letter-spacing:.05em; text-transform:uppercase;
      margin:4px 2px 0; }}
  .sb-note {{ font-size:11px; color:{SECONDARY}; text-align:center; margin-top:2px; }}
  .sb-head {{ font-size:13px; font-weight:700; margin:0 2px 6px; }}
  .sb-head span:last-child {{ display:block; margin-top:3px; }}
  .sb-head .sb-chip:first-child {{ margin-left:0; }}
  .sb-chip {{ display:inline-flex; align-items:center; gap:4px; font-size:11px; font-weight:700; color:{SECONDARY};
      margin-left:8px; }}
  .sb-chip::before {{ content:""; width:7px; height:7px; border-radius:50%; background:var(--c); }}
  [data-testid="stSidebar"] .src {{ padding:4px 2px; font-size:12px; }}
  [data-testid="stSidebar"] .stButton > button[kind="primary"] {{ background:{P["ACCENT"]}; border-color:{P["ACCENT"]};
      box-shadow:0 6px 16px rgba(242,98,46,.28); }}
  [data-testid="stSidebar"] .stButton > button[kind="primary"] p {{ color:white !important; }}
  [data-testid="stSidebar"] button[data-variant="segmented_control"],
  [data-testid="stSidebar"] button[data-testid^="stBaseButton-segmented_control"] {{ padding:0 11px; min-height:32px; }}
  /* segmented controls: black active segment; pills: orange tint (both Streamlit DOM variants) */
  button[data-variant="segmented_control"], button[data-testid="stBaseButton-segmented_control"] {{
      background:{SURFACE}; border-color:{SEPARATOR}; }}
  button[data-variant="segmented_control"] p, button[data-testid="stBaseButton-segmented_control"] p {{ color:{SECONDARY}; }}
  button[data-variant="segmented_control"][data-selected="true"], button[data-testid="stBaseButton-segmented_controlActive"] {{
      background:{P["INK"]} !important; border-color:{P["INK"]} !important; }}
  button[data-variant="segmented_control"][data-selected="true"] p,
  button[data-testid="stBaseButton-segmented_controlActive"] p {{ color:{P["ON_INK"]} !important; font-weight:600; }}
  button[data-variant="pills"][data-selected="true"], button[data-testid="stBaseButton-pillsActive"] {{
      background:{P["ACCENT_SOFT"]} !important; border-color:{P["ACCENT"]} !important; }}
  button[data-variant="pills"][data-selected="true"] p, button[data-testid="stBaseButton-pillsActive"] p {{
      color:{P["ACCENT"]} !important; font-weight:600; }}
  .brand i {{ width:30px; height:30px; border-radius:9px; background:{P["ACCENT"]}; display:inline-flex;
      align-items:center; justify-content:center; color:white; font-style:normal; font-size:15px; }}

  /* header: greeting left, user right */
  .topbar {{ display:flex; align-items:center; justify-content:space-between; gap:16px; margin:4px 0 6px; }}
  .lt {{ font-size:32px !important; font-weight:700; letter-spacing:-.8px; line-height:1.15; }}
  .lt-sub {{ font-size:14px; color:{SECONDARY}; margin:4px 0 14px; }}
  .me {{ display:flex; align-items:center; gap:10px; background:{SURFACE}; border-radius:999px; padding:5px 14px 5px 5px;
      box-shadow:0 0 0 1px {P["HAIR"]}; }}
  .me b {{ width:34px; height:34px; border-radius:50%; background:{P["ACCENT_SOFT"]}; color:{P["ACCENT"]};
      display:inline-flex; align-items:center; justify-content:center; font-size:13px; font-weight:700; }}
  .me div {{ font-size:13px; font-weight:600; line-height:1.2; }}
  .me small {{ display:block; color:{SECONDARY}; font-weight:500; font-size:11px; }}
  .h2 {{ font-size:18px; font-weight:700; letter-spacing:-.3px; margin:4px 0 10px; }}
  .h3 {{ font-size:16px; font-weight:700; margin:0 0 8px; }}

  /* tabs: a pill nav with a black active pill */
  .stTabs [role="tablist"] {{ background:{SURFACE}; border-radius:999px; padding:4px; gap:2px; width:fit-content;
      margin-bottom:18px; border:none; box-shadow:0 0 0 1px {P["HAIR"]}; }}
  .stTabs [data-testid="stTab"] {{ height:34px; padding:0 18px; border-radius:999px; background:transparent;
      border:none; display:flex; align-items:center; }}
  .stTabs [data-testid="stTab"] p {{ font-size:13px; font-weight:500; color:{SECONDARY}; }}
  .stTabs [data-testid="stTab"][aria-selected="true"] {{ background:{P["INK"]}; }}
  .stTabs [data-testid="stTab"][aria-selected="true"] p {{ color:{P["ON_INK"]}; font-weight:600; }}
  .stTabs [data-testid="stTab"]:hover p {{ color:{LABEL}; }}
  .stTabs [data-testid="stTab"][aria-selected="true"]:hover p {{ color:{P["ON_INK"]}; }}
  .stTabs [data-testid="stTab"]::after, .stTabs [role="tablist"]::after {{ display:none !important; }}
  .stTabs [role="tablist"] > :not([data-testid="stTab"]) {{ display:none !important; }}
  .stTabs [data-testid="stTab"] {{ border-bottom:none !important; }}
  .stTabs .react-aria-SelectionIndicator {{ display:none !important; }}

  /* buttons and inputs */
  .stButton > button, .stDownloadButton > button, .stLinkButton > a {{ border-radius:999px; font-weight:600; font-size:13px;
      min-height:38px; }}
  .stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] {{ background:{P["INK"]};
      border-color:{P["INK"]}; color:{P["ON_INK"]}; }}
  .stButton > button[kind="primary"]:hover {{ background:{P["ACCENT"]}; border-color:{P["ACCENT"]}; color:white; }}
  .stButton > button[kind="primary"] p, .stDownloadButton > button[kind="primary"] p {{ color:{P["ON_INK"]} !important; }}
  .stButton > button[kind="primary"]:hover p {{ color:white !important; }}
  .stButton > button[kind="primary"]:disabled {{ background:{P["FILL"]}; border-color:{P["FILL"]}; color:{GRAY}; }}
  .stButton > button[kind="secondary"], .stDownloadButton > button[kind="secondary"] {{ background:{SURFACE};
      border:1px solid {SEPARATOR}; }}
  .stMain [data-testid="stExpander"] details {{ background:{SURFACE}; border:none; border-radius:18px;
      box-shadow:0 0 0 1px {P["HAIR"]}; }}
  .stMain [data-testid="stExpander"] summary p {{ font-size:14px; font-weight:600; }}
  [data-baseweb="select"] > div, .stTextInput input, .stNumberInput input, .stTextArea textarea {{ border-radius:12px; }}
  .st-key-rr_q input {{ border-radius:999px; }}

  /* cards: any container keyed card_* */
  [class*="st-key-card"] {{ background:{SURFACE}; border-radius:22px; padding:18px 20px;
      box-shadow:0 0 0 1px {P["HAIR"]}, 0 1px 2px {P["SHADOW"]}; }}
  .c-head {{ display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:2px; }}
  .c-title {{ font-size:15px; font-weight:700; letter-spacing:-.2px; }}
  .c-sub {{ font-size:12px; color:{SECONDARY}; }}
  .big {{ font-size:34px; font-weight:800; letter-spacing:-1px; font-variant-numeric:tabular-nums; line-height:1.15; margin:6px 0 2px; }}
  .chip {{ display:inline-flex; align-items:center; gap:4px; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; }}
  .chip.up {{ background:{P["UP_BG"]}; color:{P["UP_FG"]}; }}
  .chip.down {{ background:{P["DOWN_BG"]}; color:{P["DOWN_FG"]}; }}
  .chip.flat {{ background:{P["FILL"]}; color:{SECONDARY}; }}
  .chip + span {{ font-size:11px; color:{SECONDARY}; margin-left:6px; }}

  /* KPI tiles; the first is the orange hero */
  .kpis {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
  .kpi {{ background:{SURFACE}; border-radius:20px; padding:16px 16px 14px; box-shadow:0 0 0 1px {P["HAIR"]};
      min-height:132px; display:flex; flex-direction:column; justify-content:space-between; }}
  .kpi .top {{ display:flex; justify-content:space-between; align-items:center; font-size:13px; font-weight:600; }}
  .kpi .ic {{ width:30px; height:30px; border-radius:50%; background:{P["FILL"]}; display:inline-flex;
      align-items:center; justify-content:center; }}
  .kpi .ic svg {{ width:15px; height:15px; stroke:{LABEL}; }}
  .kpi .val {{ font-size:30px; font-weight:800; letter-spacing:-.8px; font-variant-numeric:tabular-nums; }}
  .kpi .val small {{ font-size:13px; font-weight:600; color:{SECONDARY}; margin-left:4px; letter-spacing:0; }}
  .kpi.hero {{ background:linear-gradient(150deg, {P["ACCENT_2"]} 0%, {P["ACCENT"]} 55%, #D94E1F 100%); color:white;
      box-shadow:0 10px 24px rgba(242,98,46,.28); }}
  .kpi.hero .ic {{ background:rgba(255,255,255,.22); }}
  .kpi.hero .ic svg {{ stroke:white; }}
  .kpi.hero .val small, .kpi.hero .chip + span {{ color:rgba(255,255,255,.85); }}
  .kpi.hero .chip {{ background:rgba(255,255,255,.22); color:white; }}

  /* mini tiles (sources inside the briefing card) */
  .minis {{ display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin-top:12px; }}
  .mini {{ background:{P["FILL"]}; border-radius:14px; padding:10px 12px; }}
  .mini .k {{ font-size:11px; color:{SECONDARY}; font-weight:600; display:flex; align-items:center; gap:6px; }}
  .mini .k i {{ width:7px; height:7px; border-radius:50%; display:inline-block; }}
  .mini .v {{ font-size:20px; font-weight:800; font-variant-numeric:tabular-nums; margin-top:2px; }}
  .brief-txt {{ font-size:13px; color:{SECONDARY}; line-height:1.5; margin:8px 0 12px; }}

  /* recent reports table */
  .th {{ font-size:12px; color:{SECONDARY}; font-weight:600; padding:6px 0; white-space:nowrap; }}
  .td {{ font-size:13px; padding:4px 0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .td.main {{ white-space:normal; font-weight:500; line-height:1.35; }}
  .td.muted {{ color:{SECONDARY}; }}
  .st-key-card_reports [data-testid="stHorizontalBlock"] {{ border-bottom:1px solid {SEPARATOR}; padding:6px 0 14px; }}
  .st-key-card_reports [data-testid="stHorizontalBlock"]:first-of-type {{ border-bottom:none; }}
  .st-key-card_reports .stButton > button {{ min-height:30px; padding:0 8px; }}
  .st-key-card_reports .stButton > button p {{ font-size:12px; }}
  .sdot {{ display:inline-flex; align-items:center; gap:6px; font-size:12px; font-weight:600; }}
  .sdot::before {{ content:""; width:7px; height:7px; border-radius:50%; background:var(--c); }}
  .lvl {{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:11px; font-weight:700; color:white; white-space:nowrap; }}

  /* the map card and its floating sheet */
  .st-key-mapwrap {{ position:relative; border-radius:18px; overflow:hidden; background:{P["MAP_BG"]}; gap:0; }}
  .st-key-sheet {{ position:absolute; top:14px; left:14px; width:336px; max-height:612px; overflow-y:auto;
      z-index:10; background:{P["GLASS"]}; backdrop-filter:saturate(180%) blur(22px);
      -webkit-backdrop-filter:saturate(180%) blur(22px); border-radius:18px; padding:14px 14px 6px;
      box-shadow:0 0 0 1px {P["HAIR"]}, 0 10px 30px {P["SHADOW"]}; }}
  .st-key-legend {{ position:absolute; right:14px; bottom:14px; left:auto !important; width:auto !important; z-index:10; background:{P["GLASS"]};
      backdrop-filter:blur(20px); -webkit-backdrop-filter:blur(20px); border-radius:999px; padding:6px 14px;
      box-shadow:0 0 0 1px {P["HAIR"]}, 0 6px 18px {P["SHADOW"]}; }}
  .legend {{ font-size:12px; color:{SECONDARY}; display:flex; gap:12px; flex-wrap:wrap; max-width:760px; }}
  .legend span::before {{ content:""; display:inline-block; width:8px; height:8px; border-radius:50%;
      margin-right:5px; background:var(--c); vertical-align:0; }}

  /* grouped lists */
  .group {{ background:{SURFACE}; border-radius:16px; overflow:hidden; }}
  [class*="st-key-card"] .group {{ background:transparent; border-radius:0; }}
  .row {{ display:flex; align-items:center; gap:12px; padding:10px 4px; position:relative; }}
  .row + .row::before {{ content:""; position:absolute; top:0; left:36px; right:0; border-top:1px solid {SEPARATOR}; }}
  .dot {{ width:16px; height:16px; border-radius:50%; flex:none; box-shadow:inset 0 0 0 4px {P["DOT_RING"]}; }}
  .r-main {{ flex:1; min-width:0; }}
  .r-title {{ font-size:14px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .r-sub {{ font-size:12px; color:{SECONDARY}; margin-top:1px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .r-trail {{ font-size:15px; font-weight:700; font-variant-numeric:tabular-nums; }}
  .r-trail.muted {{ color:{GRAY}; font-weight:500; }}
  .sheet .row {{ padding:9px 6px; }}
  .sheet .row + .row::before {{ left:36px; }}
  .sheet-title {{ font-size:19px; font-weight:800; letter-spacing:-.3px; margin:2px 0 2px; }}
  .sheet-sub {{ font-size:12px; color:{SECONDARY}; margin-bottom:10px; }}
  .section-label {{ font-size:12px; color:{SECONDARY}; font-weight:600; margin:10px 2px 4px; }}

  /* summary strip (Facilities) */
  .strip {{ display:grid; grid-template-columns:repeat(5,1fr); background:{SURFACE}; border-radius:20px;
      box-shadow:0 0 0 1px {P["HAIR"]}; margin-top:12px; }}
  .strip > div {{ padding:14px 20px; }}
  .strip > div + div {{ border-left:1px solid {SEPARATOR}; }}
  .strip .k {{ font-size:12px; color:{SECONDARY}; font-weight:600; }}
  .strip .v {{ font-size:28px; font-weight:800; letter-spacing:-.6px; font-variant-numeric:tabular-nums; }}
  .strip .v small {{ font-size:12px; font-weight:600; color:{SECONDARY}; margin-left:4px; letter-spacing:0; }}

  .trio {{ display:grid; grid-template-columns:repeat(3,1fr); background:{P["FILL"]}; border-radius:14px; margin:6px 0 4px; }}
  .trio > div {{ padding:9px 10px; }}
  .trio > div + div {{ border-left:1px solid {SEPARATOR}; }}
  .trio .k {{ font-size:11px; color:{SECONDARY}; font-weight:600; }}
  .trio .v {{ font-size:22px; font-weight:800; font-variant-numeric:tabular-nums; }}

  .cal {{ width:44px; flex:none; text-align:center; background:{SURFACE}; border-radius:12px;
      box-shadow:0 0 0 1px {SEPARATOR}; overflow:hidden; }}
  .cal .m {{ font-size:10px; font-weight:700; color:white; background:{P["ACCENT"]}; padding:2px 0; text-transform:uppercase; }}
  .cal .d {{ font-size:18px; font-weight:800; padding:1px 0 3px; font-variant-numeric:tabular-nums; }}

  .bars .b-row {{ display:grid; grid-template-columns:150px 1fr 34px; align-items:center; gap:10px; padding:5px 0; font-size:13px; }}
  .bars .track {{ height:8px; border-radius:4px; background:{P["TRACK"]}; overflow:hidden; }}
  .bars .fill {{ height:100%; border-radius:4px; }}

  .badge {{ display:inline-block; padding:1px 8px; border-radius:6px; font-size:12px; font-weight:600; color:white; }}
  a.open {{ color:{P["ACCENT"]}; text-decoration:none; font-size:13px; font-weight:600; }}
  .card {{ background:{SURFACE}; border-radius:20px; padding:16px 18px; box-shadow:0 0 0 1px {P["HAIR"]}; height:100%; }}
  .empty {{ color:{SECONDARY}; font-size:13px; padding:16px 12px; text-align:center; }}
  .scancard {{ background:{SURFACE}; border-radius:20px; padding:14px 18px; margin:0 0 14px;
               box-shadow:0 0 0 1px {P["HAIR"]}; }}
  .scancard .hd {{ display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }}
  .scancard .hd b {{ font-size:15px; font-weight:700; }}
  .scancard .hd span {{ color:{SECONDARY}; font-size:13px; }}
  .scancard .tiers {{ display:flex; gap:8px; margin:10px 0 6px; flex-wrap:wrap; }}
  .scancard .tiers div {{ border-radius:999px; padding:5px 12px; font-size:13px; font-weight:600; }}
  .scancard .tiers em {{ font-style:normal; font-weight:800; font-size:16px; margin-right:4px; }}
  .scancard .dl {{ font-size:13px; padding:3px 0; display:flex; gap:8px; align-items:center; }}
  .scancard .dl i {{ width:8px; height:8px; border-radius:50%; display:inline-block; flex:none; }}
  [data-testid="stVegaLiteChart"] {{ border-radius:16px; overflow:hidden; }}
  .src {{ display:flex; align-items:center; gap:8px; font-size:13px; padding:3px 0; }}
  .src i {{ width:8px; height:8px; border-radius:50%; display:inline-block; flex:none; }}
  .src em {{ color:{SECONDARY}; font-style:normal; margin-left:auto; font-variant-numeric:tabular-nums; }}

  .mode {{ display:inline-flex; align-items:center; gap:6px; padding:3px 10px; border-radius:999px; font-size:11px;
      font-weight:700; vertical-align:middle; margin-left:10px; letter-spacing:.3px; }}
  .mode::before {{ content:""; width:7px; height:7px; border-radius:50%; background:currentColor; }}
  .mode.live {{ background:{P["LIVE_BG"]}; color:{P["LIVE_FG"]}; }}
  .mode.demo {{ background:{P["DEMO_BG"]}; color:{P["DEMO_FG"]}; }}
  .demo-bar {{ background:{P["DEMO_BG"]}; color:{P["DEMO_TEXT"]}; border-radius:14px; padding:9px 14px; font-size:13px; margin:0 0 14px; }}
  .brief {{ background:{SURFACE}; border-radius:20px; padding:18px 22px; box-shadow:0 0 0 1px {P["HAIR"]}; margin-top:12px; }}
  .brief h4 {{ font-size:12px; font-weight:600; color:{SECONDARY}; margin:12px 0 2px; }}
  .brief h4:first-child {{ margin-top:0; }}
  .brief p {{ font-size:15px; line-height:1.5; margin:0; max-width:80ch; }}
  .col-title {{ font-size:15px; font-weight:700; margin:18px 0 8px; }}
  .chk {{ display:flex; gap:10px; align-items:center; font-size:13px; padding:4px 0; }}
  .chk b {{ width:20px; height:20px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center;
      font-size:12px; color:white; flex:none; }}
  .icard {{ background:{SURFACE}; border-radius:18px; padding:14px 16px 10px; box-shadow:0 0 0 1px {P["HAIR"]}; }}
  .icard .top {{ display:flex; gap:8px; align-items:center; font-size:12px; font-weight:600; color:{SECONDARY}; }}
  .icard .title {{ font-size:15px; font-weight:700; margin:6px 0 4px; line-height:1.35; }}
  .icard .facts {{ display:flex; flex-wrap:wrap; gap:4px 16px; font-size:12px; color:{SECONDARY}; }}
  .icard .facts b {{ color:{LABEL}; font-weight:600; }}
  .icard .why {{ font-size:12px; color:{LABEL}; margin-top:6px; }}
  .pill {{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:11px; font-weight:700; }}
  .kv {{ display:grid; grid-template-columns:180px 1fr; gap:4px 14px; font-size:14px; margin:4px 0 10px; }}
  .kv div:nth-child(odd) {{ color:{SECONDARY}; }}
  .factor {{ display:flex; justify-content:space-between; font-size:14px; padding:5px 0; border-bottom:1px solid {SEPARATOR}; }}
  .factor span:last-child {{ font-variant-numeric:tabular-nums; font-weight:700; }}
  .health {{ display:grid; grid-template-columns:20px 120px 1fr; gap:4px 10px; font-size:13px; align-items:start; padding:8px 0;
      border-bottom:1px solid {SEPARATOR}; }}
  .health i {{ width:9px; height:9px; border-radius:50%; display:inline-block; margin-top:5px; }}
  [data-testid="stDialog"] div[role="dialog"] {{ background:{SURFACE}; color:{LABEL}; border-radius:24px; }}
  [data-testid="stSidebar"] [data-testid="stMarkdownContainer"], .stMain [data-testid="stMarkdownContainer"] {{ color:{LABEL}; }}
  :focus-visible {{ outline:3px solid {P["ACCENT"]} !important; outline-offset:2px; }}
  @media (max-width: 1100px) {{ .kpis {{ grid-template-columns:1fr; }} .strip {{ grid-template-columns:repeat(2,1fr); }} }}
  @media (prefers-reduced-motion: reduce) {{ * {{ transition:none !important; animation:none !important; }} }}
</style>"""
st.markdown("\n".join(line for line in CSS.splitlines() if line.strip()), unsafe_allow_html=True)


def split_terms(s: str) -> list[str]:
    return [t.strip() for t in re.split(r"[,\n;]", s or "") if t.strip()]


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def top_tier(items) -> str:
    """Most urgent tier among items (ACT > ALERT > WATCH > LOG), or NONE."""
    return min((r["tier"] for r in items), key=tier_rank, default="NONE")


def t_local(iso: str, fmt: str = "%b %-d, %-I:%M %p") -> str:
    d = datetime.fromisoformat(iso).astimezone(ET)
    try:
        return d.strftime(fmt)
    except ValueError:                       # Windows strftime has no %-d
        return d.strftime(fmt.replace("%-", "%#"))


def ago(iso: str) -> str:
    mins = (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds() / 60
    if mins < 1:
        return "now"
    if mins < 60:
        return f"{int(mins)} min ago"
    if mins < 60 * 24:
        return f"{int(mins // 60)} h ago"
    return t_local(iso, "%b %-d")


def short(fid: str) -> str:
    f = FACS.get(fid)
    if not f:
        return "Buffalo area"
    return f.get("short") or f["name"].split(" (")[0].split(" —")[0]


def esc(s) -> str:
    return html.escape(str(s or ""))


SOURCE_REL = {"A": "Official record or sensor", "B": "Established news outlet", "C": "Known or verified account",
              "D": "Unverified social media", "E": "Doubtful", "F": "Cannot be judged"}
CRED = {"1": "Confirmed by an analyst", "2": "Corroborated by 2+ independent sources",
        "3": "Corroborated by 1 independent source", "4": "Uncorroborated (single source)"}
STATUS_COLOR = {"new": BLUE, "in_review": ORANGE, "reviewed": ORANGE, "confirmed": RED, "unsubstantiated": GRAY,
                "false_positive": GRAY, "dismissed": GRAY, "duplicate": GRAY, "closed": GREEN}


def status_pill(s: str) -> str:
    c = STATUS_COLOR.get(s, GRAY)
    return f'<span class="pill" style="background:{c}22;color:{c}">{esc(STATUS_LABEL.get(s, s))}</span>'


def has_link(url) -> bool:
    return bool(url) and str(url).startswith("http") and mode == "Live"


def title_of(r: dict) -> str:
    t = (r.get("text") or "").strip()
    return t.split(". ")[0][:140] if t else "(no text)"


def match_basis(h) -> str:
    """How the item was tied to the site: by location or by a name in the text."""
    if h["facility_id"] == AREA_GENERAL:
        return "Mentions Buffalo but no monitored site"
    if "lat" in h.keys() and h["lat"] is not None:
        return "Location falls inside the site's geofence"
    p = matcher.fac_direct.get(h["facility_id"])
    m = p.search(h["text"] or "") if p else None
    if m:
        return f'Text names the site ("{m.group(0)}")'
    pa = matcher.fac_ambiguous.get(h["facility_id"])
    m = pa.search(h["text"] or "") if pa else None
    return f'Ambiguous name "{m.group(0)}" plus a Buffalo reference' if m else "Text match"


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.markdown(f'<div class="brand" style="margin-top:-8px"><i>◆</i><div>ThreatWatch'
                f'<div class="brand-sub">Buffalo facility monitor</div></div></div>', unsafe_allow_html=True)
    with st.container(key="sb_view"):
        mode = st.segmented_control("Data", ["Live", "Demo"], default="Live", key="mode") or "Live"
        days = st.segmented_control("Period", [1, 3, 7, 30], default=7, key="days",
                                    format_func=lambda d: f"{d}d") or 7
        level = st.segmented_control("Show", ["All", "Watch+", "Alerts"], default="Watch+", key="level") or "Watch+"
        min_tier = {"All": "LOG", "Watch+": "WATCH", "Alerts": "ALERT"}[level]
        st.segmented_control("Appearance", ["Light", "Dark"], key="appearance", on_change=_on_appearance)

if mode == "Demo":
    demo_db = DATA_DIR / "demo.db"
    if not demo_db.exists():
        from threatwatch.demo import build_demo
        build_demo()
    store = Store(demo_db)
else:
    store = Store()

fac_cfg, kw_cfg, src_cfg = load_facilities(), load_keywords(), load_sources()
matcher = Matcher(fac_cfg, kw_cfg)
FACS = {f["id"]: f for f in fac_cfg.get("facilities", [])}

now = datetime.now(timezone.utc)
end = now + timedelta(minutes=1)
start = end - timedelta(days=days)
all_rows = [dict(r) for r in store.hits_between(start, end, min_tier)]
health = intel.data_health(store, src_cfg, now)

def do_scan(send_alerts: bool = True) -> None:
    """Run one scan from the dashboard and keep a summary of it for scan_feedback()."""
    from threatwatch.pipeline import run_scan
    with st.spinner("Collecting from every source at once… usually under a minute"):
        try:
            r = run_scan(send_alerts=send_alerts, store=store)
        except Exception as e:   # the pipeline already isolates sources; this is a last resort
            st.session_state["scan_result"] = {"failed": str(e)[:300], "at": datetime.now(timezone.utc).isoformat()}
            st.session_state["flash_error"] = f"Scan failed: {str(e)[:200]}"
            return
    t = r.tier_counts()
    st.session_state["scan_result"] = {
        "at": datetime.now(timezone.utc).isoformat(), "collected": r.collected, "new": r.new_posts,
        "tiers": t, "delivery": r.delivery, "errors": r.errors, "not_configured": r.not_configured}
    st.session_state["flash"] = (f"Scan done: {r.new_posts} new, {t['ACT'] + t['ALERT']} alert, "
                                 f"{t['WATCH']} watch")


def scan_feedback(key: str) -> None:
    """Result card for the most recent dashboard scan: counts by level, delivery, problems."""
    res = st.session_state.get("scan_result")
    if not res or st.session_state.get(f"hide_scan_{res['at']}_{key}"):
        return
    if res.get("failed"):
        st.error(f"The last scan stopped: {res['failed']}")
        return
    t = res["tiers"]
    tiles = "".join(f'<div style="background:{STATUS[k]}1A;color:{STATUS[k]}"><em>{t[k]}</em>{STATUS_WORD[k]}</div>'
                    for k in ("ACT", "ALERT", "WATCH", "LOG") if t[k] or k in ("ALERT", "WATCH"))
    rows = []
    for name in ("alerts", "summary"):
        d = res["delivery"].get(name)
        if d:
            c = GREEN if d["ok"] and (d["sent"] or "skipped" not in d["message"]) else (RED if not d["ok"] else GRAY)
            msg = f'Alerts: {d["message"]}' if name == "alerts" else d["message"][0].upper() + d["message"][1:]
            rows.append(f'<div class="dl"><i style="background:{c}"></i>{esc(msg)}</div>')
    probs = {k: v for k, v in res["errors"].items() if k not in ("alerts", "summary_email")}
    if probs:
        rows.append(f'<div class="dl"><i style="background:{ORANGE}"></i>{len(probs)} source problem(s): '
                    f'{esc(", ".join(probs))} (see Admin, Data sources)</div>')
    if res["not_configured"]:
        rows.append(f'<div class="dl"><i style="background:{GRAY}"></i>Not set up: {esc(", ".join(sorted(res["not_configured"])))}</div>')
    a, b = st.columns([12, 1], vertical_alignment="top")
    a.markdown(f'<div class="scancard"><div class="hd"><b>Last scan</b><span>{ago(res["at"])} · {res["collected"]} collected · '
               f'{res["new"]} new</span></div><div class="tiers">{tiles}</div>{"".join(rows)}</div>', unsafe_allow_html=True)
    if b.button("✕", key=f"x_scan_{key}", help="Hide"):
        st.session_state[f"hide_scan_{res['at']}_{key}"] = True
        st.rerun()


def next_full_scan() -> str:
    """Local time of the next scheduled full scan (base hours in sources.yaml)."""
    base = sorted(int(h) for h in src_cfg.get("scan", {}).get("base_hours", [7, 15]))
    loc = now.astimezone(ET)
    for h in base:
        if loc.hour < h:
            return f"today {h:02d}:00"
    return f"tomorrow {base[0]:02d}:00" if base else "—"


with st.sidebar:
    with st.container(key="sb_scan"):
        if mode == "Live":
            if st.button("Run scan now", type="primary", width="stretch", key="side_scan"):
                do_scan(send_alerts=True)
                st.rerun()
            _ls = store.recent_scans(1)
            st.markdown(f'<div class="sb-note">Last scan {ago(_ls[0]["finished_at"]) if _ls else "never"} · '
                        f'next full scan {next_full_scan()}</div>', unsafe_allow_html=True)
        else:
            if st.button("Rebuild demo data", width="stretch"):
                from threatwatch.demo import build_demo
                build_demo()
                st.rerun()
    with st.container(key="sb_sources"):
        color = {"good": GREEN, "warn": ORANGE, "bad": RED, "off": GRAY}
        en = [h for h in health if h["enabled"]]
        n_good = sum(h["level"] == "good" for h in en)
        n_set = sum(h["state"] == "not_configured" for h in en)
        n_bad = sum(h["level"] == "bad" for h in en)
        chips = ("" if mode == "Demo" else
                 f'<span class="sb-chip" style="--c:{GREEN}">{n_good} ok</span>'
                 + (f'<span class="sb-chip" style="--c:{ORANGE}">{n_set} set up</span>' if n_set else "")
                 + (f'<span class="sb-chip" style="--c:{RED}">{n_bad} down</span>' if n_bad else ""))
        order = {"bad": 0, "warn": 1, "good": 2, "off": 3}
        lines = []
        for h in sorted(health, key=lambda h: (order.get(h["level"], 9), h["name"])) if mode == "Live" else health:
            note = "demo" if mode == "Demo" else ("off" if not h["enabled"] else
                                                  ago(h["last_success"]) if h["last_success"] else h["status"].lower())
            c = GRAY if mode == "Demo" else color[h["level"]]
            lines.append(f'<div class="src" title="{esc(h["status"])}"><i style="background:{c}"></i>{esc(h["name"])}'
                         f'<em>{esc(note)}</em></div>')
        st.markdown(f'<div class="sb-head"><span>Sources</span><span>{chips}</span></div>' + "".join(lines),
                    unsafe_allow_html=True)
    with st.expander("More filters"):
        cat_opts = sorted({c for r in all_rows for c in json.loads(r["categories"])}, key=matcher.label)
        cat_filter = st.multiselect("Category", cat_opts, format_func=matcher.label)
        src_filter = st.multiselect("Source", sorted({r["source_name"] for r in all_rows}))

rows = [r for r in all_rows
        if (not cat_filter or set(json.loads(r["categories"])) & set(cat_filter))
        and (not src_filter or r["source_name"] in src_filter)]

by_fac: dict[str, list[dict]] = defaultdict(list)
for r in rows:
    by_fac[r["facility_id"]].append(r)
stats = {}
for fid in list(FACS) + [AREA_GENERAL]:
    items = by_fac.get(fid, [])
    mx = max((r["score"] for r in items), default=0)
    cats = Counter(c for r in items for c in json.loads(r["categories"]))
    stats[fid] = {"items": len(items), "max": mx, "tier": top_tier(items),
                  "open": sum(r["status"] in OPEN for r in items),
                  "alerts": sum(r["tier"] in ALERT_TIERS for r in items),
                  "top": matcher.label(cats.most_common(1)[0][0]) if cats else ""}

upcoming = [dict(e) for e in store.events_between(now - timedelta(hours=6), now + timedelta(days=14))]
events_by_fac: dict[str, list[dict]] = defaultdict(list)
for e in upcoming:
    events_by_fac[e["facility_id"]].append(e)


# ------------------------------------------------------------------ incident detail dialog
def _focus(fid: str | None) -> None:
    st.session_state["focus"] = fid


def _reset_map() -> None:
    st.session_state["focus"] = None
    st.session_state["map_view"] = []


def _open_hit(hit_id: int) -> None:
    st.session_state["open_hit"] = hit_id


def _close_hit() -> None:
    st.session_state.pop("open_hit", None)


@st.dialog("Incident", width="large", on_dismiss=_close_hit)
def incident_dialog(hit_id: int):
    h = store.hit(hit_id)
    if not h:
        st.write("This item no longer exists.")
        st.button("Close", on_click=_close_hit)
        return
    cats = json.loads(h["categories"])
    st.markdown(f'<div class="icard"><div class="top"><span class="pill" style="background:{STATUS[h["tier"]]};color:white">'
                f'{PRIORITY_LABEL[h["tier"]]}</span>{status_pill(h["status"])}<span>priority score {h["score"]}/100</span></div>'
                f'<div class="title">{esc(matcher.facility_name(h["facility_id"]))}</div></div>', unsafe_allow_html=True)

    st.markdown("#### What was reported")
    st.write(h["text"])
    link = f'<a class="open" href="{esc(h["url"])}" target="_blank">Open original source</a>' if has_link(h["url"]) else \
        f'<span class="r-sub">{"Demo item, no source" if mode == "Demo" else "No link available"}</span>'
    st.markdown(f'<div class="kv"><div>Source</div><div>{esc(h["source_name"])} ({esc(h["source"])}) · {link}</div>'
                f'<div>Reported (source time)</div><div>{t_local(h["created_at"])} ET</div>'
                f'<div>Collected by ThreatWatch</div><div>{t_local(h["collected_at"] or h["detected_at"])} ET</div>'
                f'<div>Site match</div><div>{esc(match_basis(h))}</div></div>', unsafe_allow_html=True)

    st.markdown("#### Why ThreatWatch flagged it")
    st.markdown(f'<div class="kv"><div>Matched terms</div><div>{esc(", ".join(json.loads(h["terms"])))}</div>'
                f'<div>Categories</div><div>{esc(", ".join(matcher.label(c) for c in cats))}</div></div>',
                unsafe_allow_html=True)
    factors = json.loads(h["factors"] or "[]") if "factors" in h.keys() else []
    if factors:
        st.markdown("".join(f'<div class="factor"><span>{esc(t)}</span><span>{"+" if p > 0 else ""}{p}</span></div>'
                            for t, p in factors) +
                    f'<div class="factor"><span><b>Priority score</b> (review order, not a probability)</span><span>{h["score"]}</span></div>',
                    unsafe_allow_html=True)
    else:
        st.caption("Score breakdown isn't available for items collected before this version.")

    st.markdown("#### How far to trust it")
    adm = h["admiralty"] or "D4"
    st.markdown(f'<div class="kv"><div>Source reliability</div><div>{adm[0]} — {SOURCE_REL.get(adm[0], "")}</div>'
                f'<div>Information credibility</div><div>{adm[1:]} — {CRED.get(adm[1:], "")}</div>'
                f'<div>Analyst assessment</div><div>{status_pill(h["status"])} {esc(h["analyst_note"] or "")}</div></div>',
                unsafe_allow_html=True)
    rel = store.related(hit_id)
    if rel:
        indep = sum(1 for r in rel if not r["same_source"])
        st.markdown(f"#### Possibly the same event ({len(rel)})")
        st.caption(f"{indep} independent · {len(rel) - indep} same source")
        st.markdown('<div class="group">' + "".join(
            f'<div class="row"><span class="dot" style="background:{STATUS[r["tier"]]}"></span><div class="r-main">'
            f'<div class="r-title">{esc(title_of(r))}</div><div class="r-sub">{esc(r["source_name"])}, '
            f'{t_local(r["created_at"])}{" · same source" if r["same_source"] else ""} · {STATUS_LABEL.get(r["status"], r["status"])}</div></div>'
            + (f'<a class="open" href="{esc(r["url"])}" target="_blank">Open</a>' if has_link(r["url"]) else "")
            + '</div>' for r in rel[:8]) + "</div>", unsafe_allow_html=True)

    st.markdown("#### Your assessment")
    with st.form(f"assess_{hit_id}"):
        cur = h["status"] if h["status"] in STATUSES else ("in_review" if h["status"] == "reviewed" else "false_positive")
        c1, c2 = st.columns(2)
        disp = c1.selectbox("Disposition", STATUSES, index=STATUSES.index(cur), format_func=lambda s: STATUS_LABEL[s])
        conf = c2.selectbox("Your confidence", ["Not assessed", "Low", "Moderate", "High"])
        note = st.text_area("Assessment and supporting evidence", h["analyst_note"] or "", height=90)
        follow = st.text_input("Recommended follow-up", placeholder="e.g. call venue security, monitor for 24 h")
        if st.form_submit_button("Save assessment", type="primary"):
            full = note.strip()
            if conf != "Not assessed":
                full += f" | Confidence: {conf}"
            if follow.strip():
                full += f" | Follow-up: {follow.strip()}"
            store.update_hit(hit_id, status=disp, note=full)
            if mode == "Live":
                try:
                    from threatwatch.export import write_excel
                    write_excel(store, matcher)
                except Exception as e:
                    st.session_state["flash_error"] = f"Excel log not updated: {e}"
            st.session_state["flash"] = f"Saved: {STATUS_LABEL[disp]}"
            _close_hit()
            st.rerun()
    st.button("Close", key=f"close_{hit_id}", on_click=_close_hit)
    hist = store.history(hit_id)
    if hist:
        with st.expander(f"Review history ({len(hist)})"):
            for x in hist:
                st.markdown(f'<div class="r-sub">{t_local(x["changed_at"])} · {esc(STATUS_LABEL.get(x["old_status"], x["old_status"]))}'
                            f' → <b>{esc(STATUS_LABEL.get(x["new_status"], x["new_status"]))}</b> · {esc(x["note"] or "")}</div>',
                            unsafe_allow_html=True)


def incident_card(r: dict, key: str) -> None:
    corr = (f'{r["corroborating"]} independent source{"s" if r["corroborating"] != 1 else ""}'
            if r["corroborating"] else "None found")
    a, b = st.columns([6, 1], vertical_alignment="center")
    a.markdown(
        f'<div class="icard"><div class="top"><span class="pill" style="background:{STATUS[r["tier"]]};color:white">'
        f'{PRIORITY_LABEL[r["tier"]]}</span>{status_pill(r["status"])}<span>{esc(", ".join(short(x) for x in [r["facility_id"]] + r.get("also_sites", [])))}</span></div>'
        f'<div class="title">{esc(title_of(r))}</div>'
        f'<div class="facts"><span>Reported <b>{t_local(r["created_at"])}</b></span><span>Source <b>{esc(r["source_name"])}</b></span>'
        f'<span>Priority score <b>{r["score"]}</b></span><span>Corroboration <b>{corr}</b></span>'
        f'<span>Rating <b>{esc(r["admiralty"])}</b></span></div>'
        f'<div class="why">Why flagged: {esc(", ".join(json.loads(r["terms"])[:4]))} '
        f'({esc(", ".join(matcher.label(c) for c in json.loads(r["categories"])[:2]).lower())})</div></div>',
        unsafe_allow_html=True)
    b.button("Review", key=f"rv_{key}_{r['id']}", width="stretch", on_click=_open_hit, args=(r["id"],))
    if has_link(r["url"]):
        b.link_button("Source", r["url"], width="stretch")


def sort_items(items: list[dict], how: str) -> list[dict]:
    if how == "Most recent":
        return sorted(items, key=lambda r: r["created_at"], reverse=True)
    if how == "Oldest unresolved":
        return sorted([r for r in items if r["status"] in OPEN], key=lambda r: r["created_at"]) + \
            [r for r in items if r["status"] not in OPEN]
    if how == "Lowest confidence":
        return sorted(items, key=lambda r: (-int((r["admiralty"] or "D4")[1:] or 4), (r["admiralty"] or "D")[0]), reverse=False)
    if how == "Most corroborated":
        return sorted(items, key=lambda r: (-r["corroborating"], -r["score"]))
    return sorted(items, key=lambda r: (r["status"] not in OPEN, tier_rank(r["tier"]), -r["score"], r["created_at"]))


# ------------------------------------------------------------------ flash messages
if st.session_state.get("flash"):
    st.toast(st.session_state.pop("flash"))
if st.session_state.get("flash_error"):
    st.error(st.session_state.pop("flash_error"))

# ------------------------------------------------------------------ header
last_scan = store.recent_scans(1)
badge = '<span class="mode live">LIVE</span>' if mode == "Live" else '<span class="mode demo">DEMO</span>'
_hour = now.astimezone(ET).hour
_greet = "Good morning" if 5 <= _hour < 12 else "Good afternoon" if 12 <= _hour < 17 else "Good evening"
_name = load_ui().get("name") or "Nate"
st.markdown(f'<div class="topbar"><div><div class="lt">{_greet}, {esc(_name)} {badge}</div>'
            f'<div class="lt-sub">{now.astimezone(ET).strftime("%A, %B ")}{now.astimezone(ET).day} · '
            f'{("last scan " + ago(last_scan[0]["finished_at"])) if last_scan else "no scans yet"} · '
            f'{len(FACS)} sites in Buffalo and Erie County</div></div>'
            f'<div class="me"><b>{esc(_name[:1].upper())}</b><div>{esc(_name)}<small>Analyst</small></div></div></div>',
            unsafe_allow_html=True)
if mode == "Demo":
    st.markdown('<div class="demo-bar">Demo data — not real incidents.</div>', unsafe_allow_html=True)

def _lines(txt: str) -> list[str]:
    return [x.strip() for x in (txt or "").splitlines() if x.strip()]


def source_setup() -> None:
    """Admin > Data sources: connect keyed sources, switch sources on/off, edit feeds and searches."""
    from threatwatch.config import env as _env, save_source_settings, set_env
    from threatwatch.setup import CONNECT, EMAIL_FIELDS, check_source, is_connected
    srcs = src_cfg.get("sources", {})
    n_on = sum(is_connected(k) for k in CONNECT)
    st.markdown(f'<div class="h3">Connect sources <span style="font-weight:400;color:{SECONDARY}">'
                f'{n_on} of {len(CONNECT)} connected</span></div>', unsafe_allow_html=True)

    def keyed(name: str, c: dict) -> None:
        on = is_connected(name)
        with st.expander(f'{"✓" if on else "○"}  {c["title"]} — {c["adds"]}',
                         expanded=f"check_{name}" in st.session_state):
            a, b = st.columns([3, 1], vertical_alignment="center")
            a.markdown(f'<div class="r-sub" style="white-space:normal">{esc(c["steps"])}'
                       + (f' About {c["minutes"]} min.' if c["minutes"] else "") + "</div>", unsafe_allow_html=True)
            b.link_button("Get a key ↗", c["url"], width="stretch")
            vals = {}
            cols = st.columns(len(c["fields"]))
            for col, (k, label, secret) in zip(cols, c["fields"]):
                have = bool(_env(k)) and _env(k) != "yourname.bsky.social"
                vals[k] = col.text_input(label, type="password" if secret else "default",
                                         value="" if secret else (_env(k) or ""),
                                         placeholder="saved — leave blank to keep" if (secret and have) else "",
                                         key=f"env_{k}")
            extra = {}
            if name == "telegram":
                chans = srcs.get("telegram", {}).get("channels", []) or []
                txt = st.text_area("Public channels (one username per line)", key="tg_ch",
                                   value="\n".join(ch["username"] if isinstance(ch, dict) else str(ch) for ch in chans))
                extra["channels"] = [{"username": u.lstrip("@").split("/")[-1], "reliability": "C", "local": True}
                                     for u in _lines(txt)]
            if name == "youtube":
                extra["queries"] = _lines(st.text_area("Searches (one per line)", key="yt_q",
                                                       value="\n".join(srcs.get("youtube", {}).get("queries", []))))
            if name == "reddit":
                extra["subreddits"] = _lines(st.text_area("Subreddits (one per line)", key="rd_s",
                                                          value="\n".join(srcs.get("reddit", {}).get("subreddits", []))))
            enabled = st.toggle("Use this source in scans", value=bool(srcs.get(name, {}).get("enabled")), key=f"on_{name}")
            s1, s2, _ = st.columns([1, 1, 3])
            save, test = s1.button("Save", key=f"save_{name}"), s2.button("Save & test", type="primary", key=f"test_{name}")
            if save or test:
                set_env({k: v.strip() for k, v in vals.items() if v.strip()})
                save_source_settings(name, {"enabled": enabled, **extra})
                st.session_state["flash"] = f"{c['title']} saved"
                if test:
                    st.session_state[f"check_{name}"] = check_source(name)
                st.rerun()
            res = st.session_state.get(f"check_{name}")
            if res:
                (st.success if res["ok"] else st.error)(res["message"])
                for line in res.get("sample", []):
                    st.markdown(f'<div class="r-sub">· {esc(line)}</div>', unsafe_allow_html=True)

    for name, c in CONNECT.items():
        keyed(name, c)

    chans = [x.strip() for x in (_env("ALERT_CHANNELS", "console") or "").split(",") if x.strip()]
    with st.expander(f'{"✓" if "email" in chans and _env("ALERT_EMAIL_TO") else "○"}  Email — alerts and a summary after every scan'):
        st.markdown('<div class="r-sub" style="white-space:normal">Gmail: server smtp.gmail.com, port 587, your address, '
                    'and an app password (Google Account → Security → App passwords).</div>', unsafe_allow_html=True)
        vals = {}
        cols = st.columns(len(EMAIL_FIELDS))
        for col, (k, label, secret) in zip(cols, EMAIL_FIELDS):
            vals[k] = col.text_input(label, type="password" if secret else "default", value="" if secret else (_env(k) or ""),
                                     placeholder="saved — leave blank to keep" if (secret and _env(k)) else "", key=f"env_{k}")
        want = st.toggle("Send email", value="email" in chans, key="mail_on")
        s1, s2, _ = st.columns([1, 1.3, 2.7])
        m_save, m_test = s1.button("Save", key="mail_save"), s2.button("Save & send test", type="primary", key="mail_test")
        if m_save or m_test:
            new = [x for x in chans if x != "email"] + (["email"] if want else [])
            set_env({**{k: v.strip() for k, v in vals.items() if v.strip()}, "ALERT_CHANNELS": ",".join(new or ["console"])})
            if m_test:
                from threatwatch.alerts import EmailNotifier, build_scan_summary
                from threatwatch.pipeline import ScanResult
                try:
                    subj, text, html_ = build_scan_summary(ScanResult(), matcher)
                    EmailNotifier().send_text("[TEST] " + subj, text, html_)
                    st.session_state["flash"] = f"Test email sent to {_env('ALERT_EMAIL_TO')}"
                except Exception as e:
                    st.session_state["flash_error"] = f"Email failed: {e}"
            else:
                st.session_state["flash"] = "Email settings saved"
            st.rerun()

    with st.expander("Free sources — feeds, searches, hashtags"):
        free = ["news", "gdelt", "nws", "tfr", "mastodon", "bluesky", "opendata", "adsb", "schedules"]
        cols = st.columns(4)
        flags = {n: cols[i % 4].toggle(n, value=bool(srcs.get(n, {}).get("enabled")), key=f"free_{n}")
                 for i, n in enumerate(free)}
        feeds = pd.DataFrame(srcs.get("news", {}).get("feeds", []), columns=["name", "url", "reliability"])
        st.markdown('<div class="section-label">News feeds (RSS)</div>', unsafe_allow_html=True)
        feeds_ed = st.data_editor(feeds, num_rows="dynamic", hide_index=True, width="stretch", key="feeds_ed",
                                  column_config={"reliability": st.column_config.SelectboxColumn(
                                      options=["A", "B", "C", "D"], default="B")})
        q1, q2 = st.columns(2)
        extra_q = q1.text_area("Extra news searches (one per line)", key="news_q",
                               value="\n".join(srcs.get("news", {}).get("extra_queries", [])))
        tags = q2.text_area("Mastodon hashtags (one per line, no #)", key="m_tags",
                            value="\n".join(srcs.get("mastodon", {}).get("tags", [])))
        if st.button("Save free sources", type="primary", key="free_save"):
            good = [{"name": r["name"], "url": r["url"], "reliability": r.get("reliability") or "B"}
                    for r in feeds_ed.to_dict("records") if r.get("name") and str(r.get("url", "")).startswith("http")]
            for n, v in flags.items():
                save_source_settings(n, {"enabled": v})
            save_source_settings("news", {"feeds": good, "extra_queries": _lines(extra_q)})
            save_source_settings("mastodon", {"tags": [t.lstrip("#") for t in _lines(tags)]})
            st.session_state["flash"] = "Free sources saved"
            st.rerun()


tab_dash, tab_inc, tab_fac, tab_rep, tab_col, tab_admin = st.tabs(
    ["Dashboard", "Incidents", "Facilities", "Reports", "Collection log", "Admin"])

# ================================================================== DASHBOARD
with tab_dash:
    B = intel.briefing(store, matcher, src_cfg, now, days, demo=mode == "Demo")
    if mode == "Live":
        scan_feedback("dash")

    # ---- first-run checklist
    if mode == "Live" and not st.session_state.get("hide_checklist"):
        from threatwatch.config import env as _env, REPORTS_DIR
        reviewed_any = store.conn.execute("SELECT COUNT(*) FROM review_history").fetchone()[0] > 0
        steps = [("Monitored sites set up", bool(FACS)),
                 ("Sources checked (at least one working)", any(h["level"] == "good" for h in health)),
                 ("First scan run", B["scans"] > 0),
                 ("First flagged item reviewed", reviewed_any),
                 ("Alert delivery set to email or Teams", any(c in (_env("ALERT_CHANNELS", "") or "") for c in ("email", "teams"))),
                 ("First report generated", any(REPORTS_DIR.glob("*.docx")))]
        if not all(ok for _, ok in steps):
            with st.expander(f"Getting started: {sum(ok for _, ok in steps)} of {len(steps)} done", expanded=B["scans"] == 0):
                st.markdown("".join(f'<div class="chk"><b style="background:{GREEN if ok else GRAY}">{"✓" if ok else ""}</b>{t}</div>'
                                    for t, ok in steps), unsafe_allow_html=True)
                if st.button("Hide checklist"):
                    st.session_state["hide_checklist"] = True
                    st.rerun()

    # ---- row 1: briefing · KPI tiles · activity chart
    M, CH = B["metrics"], B["changes"]
    focus = st.session_state.get("focus")
    scope = by_fac.get(focus, []) if focus else rows
    ch = {lbl: (p, c) for lbl, p, c in CH["rows"]}

    def chip(lbl: str, note: str = "vs prior 24 h") -> str:
        p, c = ch.get(lbl, (0, 0))
        d = c - p
        cls = "flat" if d == 0 else ("up" if d > 0 else "down")   # more threat reporting = up (red)
        return f'<span class="chip {cls}">{"▲" if d > 0 else "▼" if d < 0 else "•"} {abs(d)}</span><span>{note}</span>'

    ICON = {
        "alert": '<path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>',
        "pin": '<path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/>',
        "link": '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
        "radar": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6-6"/>',
    }

    def kpi(title, value, small, icon, foot, hero=False):
        svg = f'<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{ICON[icon]}</svg>'
        return (f'<div class="kpi{" hero" if hero else ""}"><div class="top"><span>{title}</span><span class="ic">{svg}</span></div>'
                f'<div><div class="val">{value}<small>{small}</small></div><div style="margin-top:4px">{foot}</div></div></div>')

    enabled = [h for h in health if h["enabled"]]
    n_ok = sum(h["level"] == "good" for h in enabled)
    n_setup = sum(h["state"] == "not_configured" for h in enabled)
    n_down = sum(h["level"] == "bad" for h in enabled)
    r1a, r1b, r1c = st.columns([1.1, 1.3, 1.35], gap="medium")
    with r1a, st.container(key="card_brief"):
        st.markdown(f'<div class="c-head"><span class="c-title">Awaiting review</span><span class="c-sub">last {days} d</span></div>'
                    f'<div class="big">{M["awaiting_review"]}</div>{chip("Still awaiting review")}'
                    f'<div class="brief-txt">{esc(B["observation"])}<br>{esc(B["unknowns"])}</div>',
                    unsafe_allow_html=True)
        b1, b2 = st.columns(2)
        if b1.button("Run scan", type="primary", key="brief_scan", width="stretch", disabled=mode == "Demo"):
            do_scan(send_alerts=True)
            st.rerun()
        if st.session_state.get("brief_report") and Path(st.session_state["brief_report"]).exists():
            rp = Path(st.session_state["brief_report"])
            b2.download_button("Download report", rp.read_bytes(), file_name=rp.name, width="stretch", key="brief_dl",
                               mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        elif b2.button("Report", key="brief_rep", width="stretch", help="Executive briefing (Word)"):
            from threatwatch.report import build_report
            st.session_state["brief_report"] = build_report("executive", store=store, days=days, demo=mode == "Demo")
            st.rerun()
        minis = ([("Working", n_ok, GREEN), ("Not set up", n_setup, GRAY), ("Down", n_down, RED)] if mode == "Live"
                 else [("Sources", "demo", GRAY), ("Sites", len(FACS), ACCENT), ("Scans", B["scans"], INK)])
        st.markdown('<div class="minis">' + "".join(
            f'<div class="mini"><div class="k"><i style="background:{c}"></i>{k}</div><div class="v">{v}</div></div>'
            for k, v, c in minis) + "</div>", unsafe_allow_html=True)
    with r1b:
        st.markdown('<div class="kpis">'
                    + kpi("High priority", M["high_priority"], "open", "alert", chip("Alert and Watch items"), hero=True)
                    + kpi("Sites needing attention", M["sites_attention"], f"of {len(FACS)}", "pin",
                          f'<span class="c-sub">{len([e for e in upcoming if e["facility_id"] in FACS])} events in 14 days</span>')
                    + kpi("Corroborated", M["corroborated"], "reports", "link",
                          f'<span class="c-sub">by an independent source</span>')
                    + kpi("Coverage", "Demo" if mode == "Demo" else M["coverage"], "", "radar",
                          chip("Distinct sources reporting", "sources vs prior 24 h"))
                    + "</div>", unsafe_allow_html=True)
    with r1c, st.container(key="card_activity"):
        st.markdown(f'<div class="c-head"><span class="c-title">Activity</span><span class="c-sub">'
                    f'{esc(short(focus)) + " · " if focus else ""}reports per day</span></div>', unsafe_allow_html=True)
        day_list = [(end - timedelta(days=i)).astimezone(ET).strftime("%a %d") for i in range(min(max(days, 7), 14) - 1, -1, -1)]
        df = pd.DataFrame([{"day": datetime.fromisoformat(r["created_at"]).astimezone(ET).strftime("%a %d"),
                            "level": STATUS_WORD[r["tier"]]} for r in scope] or [{"day": day_list[-1], "level": "Watch"}])
        df = df[df["day"].isin(day_list)]
        if not scope or df.empty:
            st.markdown('<div class="empty" style="padding:70px 10px">No reports in this period yet.</div>',
                        unsafe_allow_html=True)
        chart = None if (not scope or df.empty) else alt.Chart(df).mark_bar(cornerRadius=5, size=14).encode(
            x=alt.X("day:O", sort=day_list, title=None, axis=alt.Axis(labelAngle=0, domain=False, ticks=False,
                                                                       labelColor=SECONDARY, labelFontSize=10,
                                                                       labelExpr="slice(datum.label, 0, 3)")),
            y=alt.Y("count():Q", title=None, axis=alt.Axis(grid=True, gridColor=P["TRACK"], gridDash=[3, 3], domain=False,
                                                           ticks=False, labelColor=SECONDARY, tickMinStep=1)),
            color=alt.Color("level:N", scale=alt.Scale(domain=["Act now", "Alert", "Watch", "Logged"],
                                                       range=[ACT_RED, ACCENT, P["WATCH"], P["CHART_LOG"]]),
                            legend=alt.Legend(orient="top", title=None, direction="horizontal", labelColor=SECONDARY,
                                              symbolType="circle", labelFontSize=11, offset=6)),
            order=alt.Order("level:N", sort="ascending"),
            tooltip=[alt.Tooltip("day:O"), alt.Tooltip("level:N"), alt.Tooltip("count():Q", title="items")]
        ).properties(height=236).configure_view(strokeWidth=0).configure(
            font=FONT, background=SURFACE, padding={"left": 0, "right": 0, "top": 4, "bottom": 0})
        if chart is not None:
            st.altair_chart(chart, width="stretch")

    # ---- row 2: actions, changes, gaps · recent reports table
    left, right = st.columns([1, 2.3], gap="medium")
    with left:
        with st.container(key="card_actions"):
            st.markdown('<div class="c-title">Priority actions</div>', unsafe_allow_html=True)
            if not B["priority"]:
                st.markdown('<div class="empty">Nothing open needs review.</div>', unsafe_allow_html=True)
            for r in B["priority"][:4]:
                a, b = st.columns([3, 1.5], vertical_alignment="center")
                a.markdown(f'<div class="r-title" style="white-space:normal">'
                           f'<span class="dot" style="display:inline-block;width:9px;height:9px;background:{STATUS[r["tier"]]};margin-right:6px;box-shadow:none"></span>'
                           f'{esc(", ".join(short(x) for x in [r["facility_id"]] + r.get("also_sites", [])))}</div>'
                           f'<div class="r-sub" style="white-space:normal">{esc(title_of(r)[:80])}</div>', unsafe_allow_html=True)
                b.button("Review", key=f"pa_{r['id']}", width="stretch", on_click=_open_hit, args=(r["id"],))
        with st.container(key="card_changes"):
            st.markdown('<div class="c-head"><span class="c-title">Last 24 h</span>'
                        + ('' if CH["enough_history"] else '<span class="c-sub">baseline after 48 h</span>') + "</div>"
                        + '<div class="group">' + "".join(
                            f'<div class="row" style="padding:8px 0"><div class="r-main"><div class="r-title">{esc(lbl)}</div>'
                            f'<div class="r-sub">{esc(intel.compare(p, c))}</div></div></div>' for lbl, p, c in CH["rows"])
                        + "</div>", unsafe_allow_html=True)
            for n in CH["notable"][:2]:
                st.markdown(f'<div class="r-sub" style="white-space:normal;margin-top:6px">{esc(n["text"].split(" (")[0])}</div>',
                            unsafe_allow_html=True)
        with st.container(key="card_gaps"):
            st.markdown('<div class="c-title">Monitoring gaps</div>', unsafe_allow_html=True)
            if mode == "Demo":
                st.markdown('<div class="empty">Demo data uses no live sources.</div>', unsafe_allow_html=True)
            elif not B["gaps"]:
                st.markdown('<div class="empty">All enabled sources are working.</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="group">' + "".join(
                    f'<div class="row" style="padding:8px 0"><span class="dot" style="width:9px;height:9px;box-shadow:none;'
                    f'background:{RED if g["level"] == "bad" else ORANGE}"></span>'
                    f'<div class="r-main"><div class="r-title">{esc(g["name"])}</div><div class="r-sub">{esc(g["status"])}</div>'
                    f'</div></div>' for g in B["gaps"][:7]) + "</div>", unsafe_allow_html=True)
    with right, st.container(key="card_reports"):
        h1, h2, h3, h4 = st.columns([1.15, 1.05, 2.2, 1.35], vertical_alignment="center")
        h1.markdown(f'<div class="c-title">Recent reports</div><div class="c-sub">'
                    f'{esc(short(focus)) if focus else "All sites"} · last {days} d</div>', unsafe_allow_html=True)
        rq = h2.text_input("Search", placeholder="Search", key="rr_q", label_visibility="collapsed")
        rlvl = h3.segmented_control("Level", ["All", "Act", "Alert", "Watch"], default="All", key="rr_lvl",
                                    label_visibility="collapsed") or "All"
        sort_how = h4.selectbox("Sort", ["Highest priority", "Most recent", "Oldest unresolved", "Lowest confidence",
                                         "Most corroborated"], key="dash_sort", label_visibility="collapsed")
        pool = [r for r in sort_items(scope, sort_how) if r["status"] in OPEN and r["tier"] in REVIEW_TIERS]
        if rlvl != "All":
            pool = [r for r in pool if r["tier"] == {"Act": "ACT", "Alert": "ALERT", "Watch": "WATCH"}[rlvl]]
        if rq:
            ql = rq.lower()
            pool = [r for r in pool if ql in (r["text"] or "").lower() or ql in (r["source_name"] or "").lower()
                    or ql in short(r["facility_id"]).lower()]
        queue = intel.collapse(pool)[:10]
        COLS = [1.35, 2.8, 1.0, .62, .62, .95, .95, 1.1]
        hdr = st.columns(COLS)
        for c, t in zip(hdr, ["Site", "Report", "Level", "Score", "Rating", "Status", "Reported", ""]):
            c.markdown(f'<div class="th">{t}</div>', unsafe_allow_html=True)
        if not queue:
            st.markdown('<div class="empty">No open Alert or Watch items for this filter.</div>', unsafe_allow_html=True)
        for r in queue:
            cs = st.columns(COLS, vertical_alignment="center")
            cs[0].markdown(f'<div class="td" style="font-weight:600">{esc(", ".join(short(x) for x in [r["facility_id"]] + r.get("also_sites", [])))}'
                           f'</div><div class="td muted" style="font-size:11px">{esc(r["source_name"])}</div>', unsafe_allow_html=True)
            cs[1].markdown(f'<div class="td main">{esc(title_of(r)[:110])}</div>', unsafe_allow_html=True)
            cs[2].markdown(f'<span class="lvl" style="background:{STATUS[r["tier"]]};color:{P["ON_INK"] if r["tier"] == "WATCH" else "white"}">'
                           f'{STATUS_WORD[r["tier"]]}</span>', unsafe_allow_html=True)
            cs[3].markdown(f'<div class="td" style="font-weight:700">{r["score"]}</div>', unsafe_allow_html=True)
            cs[4].markdown(f'<div class="td muted">{esc(r["admiralty"])}</div>', unsafe_allow_html=True)
            cs[5].markdown(f'<span class="sdot" style="--c:{STATUS_COLOR.get(r["status"], GRAY)}">'
                           f'{esc(STATUS_LABEL.get(r["status"], r["status"]))}</span>', unsafe_allow_html=True)
            cs[6].markdown(f'<div class="td">{t_local(r["created_at"], "%b %-d")}</div>'
                           f'<div class="td muted" style="font-size:11px">{t_local(r["created_at"], "%-I:%M %p")}</div>',
                           unsafe_allow_html=True)
            cs[7].button("Open", key=f"rr_{r['id']}", on_click=_open_hit, args=(r["id"],), width="stretch")
        if len(pool) > len(queue):
            st.caption(f"{len(pool) - len(queue)} more under Incidents.")

    # ---- map
    with st.container(key="card_map"):
        mh1, mh2 = st.columns([4, 1.2], vertical_alignment="center")
        mh1.markdown('<div class="c-title">Map</div>', unsafe_allow_html=True)
        mc3 = mh2
        mc1, mc2 = st.columns([1.2, 3.0], vertical_alignment="bottom")
        win = mc1.segmented_control("Time", ["Latest", "6 h", "24 h", "7 d"], default="24 h", key="map_win") or "24 h"
        LAYERS = ["Reports", "Heat", "Aircraft", "Vessels", "Police incidents", "Traffic", "Events"]
        layers_on = mc2.pills("Layers", LAYERS, selection_mode="multi", key="layers",
                              default=["Reports", "Aircraft", "Vessels", "Police incidents", "Traffic", "Events"]) or []
        view_opts = mc3.pills("View", ["3D", "Large"], selection_mode="multi", key="map_view",
                              label_visibility="collapsed") or []
        win_h = {"Latest": 1, "6 h": 6, "24 h": 24, "7 d": 168}[win]
        since = now - timedelta(hours=win_h)
        track_since = now - timedelta(hours=max(win_h, 1))

        fences = []
        for fid, f in FACS.items():
            s = stats[fid]
            c = STATUS[s["tier"]]
            tip = (f"<b>{esc(f['name'])}</b><br/>Monitored site · geofence {f.get('radius_km', .5)} km<br/>"
                   f"{STATUS_WORD[s['tier']]}" + (f", top priority score {s['max']}<br/>{s['items']} flagged item(s) in the "
                                                  f"last {days} d, {s['open']} open" if s["items"] else " — nothing flagged"))
            fences.append({"id": fid, "lat": f["lat"], "lon": f["lon"], "r": float(f.get("radius_km", .5)) * 1000,
                           "fill": rgb(c, 70 if s["items"] else 28), "line": rgb(c, 235 if s["items"] else 120), "tip": tip,
                           "h": max(s["max"], 4) * (4 if focus in FACS else 18), "col": rgb(c, 210 if s["items"] else 90)})
        layers = []
        if "Heat" in layers_on:
            heat = []
            for r in rows:
                f = FACS.get(r["facility_id"])
                if f and r["created_at"] >= since.isoformat():
                    rnd = random.Random(r["id"])
                    sp = float(f.get("radius_km", .5)) / 111 * .8
                    heat.append({"lat": f["lat"] + rnd.uniform(-sp, sp), "lon": f["lon"] + rnd.uniform(-sp, sp), "w": r["score"]})
            if heat:
                layers.append(pdk.Layer("HeatmapLayer", id="heat", data=heat, get_position="[lon, lat]", get_weight="w",
                                        radius_pixels=60, opacity=.45, threshold=.08,
                                        color_range=[rgb("#FFE08A", 30), rgb(YELLOW, 90), rgb(ORANGE, 140),
                                                     rgb("#FF6A3D", 180), rgb(RED, 210), rgb("#C7000B", 230)]))
        layers.append(pdk.Layer("ScatterplotLayer", id="fences", data=fences, get_position="[lon, lat]", get_radius="r",
                                get_fill_color="fill", get_line_color="line", line_width_min_pixels=1.5, stroked=True,
                                filled=True, pickable=True, auto_highlight=True, highlight_color=rgb(BLUE, 60)))
        if "3D" in view_opts:   # site columns: height = highest priority score
            layers.append(pdk.Layer("ColumnLayer", id="columns", data=fences, get_position="[lon, lat]", get_elevation="h",
                                    radius=22 if focus in FACS else 70, get_fill_color="col", pickable=True,
                                    auto_highlight=True, extruded=True))
        if "Reports" in layers_on:   # one pin per flagged report, placed inside its site's geofence
            pins = []
            for r in rows:
                f = FACS.get(r["facility_id"])
                if not f or r["created_at"] < since.isoformat() or r["status"] in INACTIVE:
                    continue
                rnd = random.Random(r["id"])
                sp = float(f.get("radius_km", .5)) / 111 * .55
                lat, lon = (r["lat"], r["lon"]) if r.get("lat") else (f["lat"] + rnd.uniform(-sp, sp), f["lon"] + rnd.uniform(-sp, sp))
                pins.append({"hit": r["id"], "lat": lat, "lon": lon, "c": rgb(STATUS[r["tier"]]),
                             "tip": f"<b>{esc(PRIORITY_LABEL[r['tier']])} · {r['score']}</b> · {esc(short(r['facility_id']))}<br/>"
                                    f"{esc(title_of(r)[:120])}<br/>{esc(r['source_name'])} · {t_local(r['created_at'])}<br/>"
                                    f"<i>Click to open</i>"})
            layers.append(pdk.Layer("ScatterplotLayer", id="reports", data=pins, get_position="[lon, lat]", get_radius=1,
                                    radius_min_pixels=7, radius_max_pixels=9, get_fill_color="c", stroked=True,
                                    get_line_color=[255, 255, 255, 255], line_width_min_pixels=2, pickable=True,
                                    auto_highlight=True))
        if focus in FACS:
            layers.append(pdk.Layer("ScatterplotLayer", id="focus", data=[g for g in fences if g["id"] == focus],
                                    get_position="[lon, lat]", get_radius="r", filled=False, stroked=True,
                                    get_line_color=rgb(BLUE), line_width_min_pixels=3))
        if "Events" in layers_on:
            ev_fac = [{"lat": FACS[f]["lat"], "lon": FACS[f]["lon"], "r": float(FACS[f].get("radius_km", .5)) * 1000 + 90,
                       "tip": f"<b>{esc(evs[0]['name'])}</b><br/>Scheduled event at {esc(short(f))}<br/>"
                              + t_local(evs[0]["start_at"], "%a %b %-d, %-I:%M %p") + f" · {esc(evs[0]['source'])}"}
                      for f, evs in events_by_fac.items() if f in FACS]
            layers.append(pdk.Layer("ScatterplotLayer", id="events", data=ev_fac, get_position="[lon, lat]", get_radius="r",
                                    filled=False, stroked=True, get_line_color=rgb(BLUE, 200), line_width_min_pixels=2,
                                    pickable=True))
        if "Police incidents" in layers_on:
            inc = [{"lat": p["lat"], "lon": p["lon"], "tip": f"<b>Police-reported incident</b> · {t_local(p['created_at'])}<br/>"
                    f"{esc(p['text'][:150])}", "url": p["url"]} for p in store.geo_posts(("opendata",), since)]
            layers.append(pdk.Layer("ScatterplotLayer", id="incidents", data=inc, get_position="[lon, lat]", get_radius=1,
                                    radius_min_pixels=5, get_fill_color=rgb(INDIGO, 230), stroked=True,
                                    get_line_color=[255, 255, 255, 255], line_width_min_pixels=1.5, pickable=True))
        if "Traffic" in layers_on:
            trf = [{"lat": p["lat"], "lon": p["lon"], "tip": f"<b>Traffic event</b> · {t_local(p['created_at'])}<br/>"
                    f"{esc(p['text'][:150])}", "url": p["url"]} for p in store.geo_posts(("ny511",), since)]
            layers.append(pdk.Layer("ScatterplotLayer", id="traffic", data=trf, get_position="[lon, lat]", get_radius=1,
                                    radius_min_pixels=5, get_fill_color=rgb(YELLOW, 255), stroked=True,
                                    get_line_color=rgb("#8A6D00"), line_width_min_pixels=1.5, pickable=True))
        if "Vessels" in layers_on:
            ves = [{"lat": t["lat"], "lon": t["lon"],
                    "tip": f"<b>{esc(t['name'] or 'MMSI ' + t['ident'])}</b> · vessel<br/>{json.loads(t['info']).get('sog', '?')} kn, "
                           f"{esc(json.loads(t['info']).get('status', ''))}<br/>Seen {ago(t['seen_at'])}"}
                   for t in store.tracks_since("vessel", track_since)]
            layers.append(pdk.Layer("ScatterplotLayer", id="vessels", data=ves, get_position="[lon, lat]", get_radius=1,
                                    radius_min_pixels=6, get_fill_color=rgb(CYAN), stroked=True,
                                    get_line_color=[255, 255, 255, 255], line_width_min_pixels=2, pickable=True))
        if "Aircraft" in layers_on:
            low_ac, high_ac = [], []
            for t in store.tracks_since("aircraft", track_since):
                info = json.loads(t["info"])
                low = isinstance(info.get("alt"), (int, float)) and info["alt"] <= 2000
                (low_ac if low else high_ac).append({
                    "lat": t["lat"], "lon": t["lon"],
                    "tip": f"<b>{esc(t['name'] or t['ident'])}</b> {esc(info.get('type') or '')} · aircraft<br/>"
                           f"{info.get('alt', '?')} ft, {info.get('gs', '?')} kt<br/>Seen {ago(t['seen_at'])}",
                    "url": f"https://globe.adsb.lol/?icao={t['ident']}"})
            for lid, data, px, alpha in (("aircraft_high", high_ac, 4, 150), ("aircraft_low", low_ac, 7, 255)):
                layers.append(pdk.Layer("ScatterplotLayer", id=lid, data=data, get_position="[lon, lat]", get_radius=1,
                                        radius_min_pixels=px, radius_max_pixels=px + 2, get_fill_color=rgb(PURPLE, alpha),
                                        stroked=True, get_line_color=[255, 255, 255, 230], line_width_min_pixels=1.5, pickable=True))
        if focus in FACS:
            import math
            z = max(11.5, min(15.0, 14.2 - math.log2(max(.2, float(FACS[focus].get("radius_km", .5))) / .4)))
            shift = 190 * 360 / (512 * 2 ** z)
            view = pdk.ViewState(latitude=FACS[focus]["lat"], longitude=FACS[focus]["lon"] - shift, zoom=z,
                                 pitch=45 if "3D" in view_opts else 0)
        else:
            view = pdk.ViewState(latitude=42.895, longitude=-78.905, zoom=11.15, pitch=45 if "3D" in view_opts else 0,
                                 bearing=-12 if "3D" in view_opts else 0)
        map_h = 820 if "Large" in view_opts else 600
        deck = pdk.Deck(layers=layers, initial_view_state=view, map_style=pdk.map_styles.CARTO_DARK if THEME == "dark" else pdk.map_styles.CARTO_ROAD,
                        tooltip={"html": "{tip}", "style": {"backgroundColor": P["TOOLTIP_BG"], "color": LABEL,
                                                            "fontSize": "12px", "borderRadius": "10px", "padding": "8px 10px",
                                                            "maxWidth": "320px", "boxShadow": "0 6px 20px rgba(0,0,0,.15)",
                                                            "fontFamily": FONT}})

        with st.container(key="mapwrap"):
            event = st.pydeck_chart(deck, on_select="rerun", selection_mode="single-object", key=f"map_{map_h}", height=map_h)
            objs = ((event.selection or {}).get("objects") or {}) if event else {}
            sel_layer = next(iter(objs), None)
            sel = objs[sel_layer][0] if sel_layer and objs[sel_layer] else None
            if sel_layer in ("fences", "columns") and sel and sel["id"] != focus:
                st.session_state["focus"] = sel["id"]
                st.rerun()
            if sel_layer == "reports" and sel and st.session_state.get("_last_pin") != sel["hit"]:
                st.session_state["_last_pin"] = sel["hit"]   # open each clicked report once
                _open_hit(sel["hit"])
            picked_marker = sel if sel_layer in ("incidents", "traffic", "vessels", "aircraft_low", "aircraft_high", "events") else None
            with st.container(key="sheet"):
                ranked = sorted(FACS, key=lambda f: (-stats[f]["max"], -stats[f]["items"], short(f)))
                if picked_marker:
                    st.markdown(f'<div class="section-label">Selected</div><div class="group"><div class="row"><div class="r-main">'
                                f'<div class="r-sub" style="white-space:normal;color:{LABEL}">{picked_marker["tip"]}</div>'
                                f'</div></div></div>', unsafe_allow_html=True)
                    if has_link(picked_marker.get("url")):
                        st.link_button("Open source ↗", picked_marker["url"])
                choice = st.selectbox("Find a site", ["All sites"] + ranked, label_visibility="collapsed",
                                      index=(ranked.index(focus) + 1) if focus in ranked else 0,
                                      format_func=lambda f: "Search sites" if f == "All sites" else FACS[f]["name"],
                                      key=f"find_{focus}")
                new_focus = None if choice == "All sites" else choice
                if new_focus != focus:
                    st.session_state["focus"] = new_focus
                    st.rerun()
                if focus in FACS:
                    f, s = FACS[focus], stats[focus]
                    if st.button("‹ All sites", type="tertiary", key="back"):
                        st.session_state["focus"] = None
                        st.rerun()
                    st.markdown(
                        f'<div class="sheet"><div class="sheet-title">{esc(f["name"].split(" (")[0])}</div>'
                        f'<div class="sheet-sub">{esc(f.get("address", ""))}</div>'
                        f'<div class="trio"><div><div class="k">Status</div><div class="v" style="color:{STATUS[s["tier"]]};font-size:17px;line-height:1.6">'
                        f'{STATUS_WORD[s["tier"]]}</div></div><div><div class="k">Open</div><div class="v">{s["open"]}</div></div>'
                        f'<div><div class="k">Flagged</div><div class="v">{s["items"]}</div></div></div></div>', unsafe_allow_html=True)
                    if events_by_fac.get(focus):
                        e = events_by_fac[focus][0]
                        st.markdown(f'<div class="section-label">Next event</div><div class="group"><div class="row">'
                                    f'<div class="cal"><div class="m">{t_local(e["start_at"], "%b")}</div>'
                                    f'<div class="d">{t_local(e["start_at"], "%-d")}</div></div><div class="r-main">'
                                    f'<div class="r-title">{esc(e["name"])}</div><div class="r-sub">'
                                    f'{t_local(e["start_at"], "%a, %-I:%M %p")}</div></div></div></div>', unsafe_allow_html=True)
                    st.markdown('<div class="section-label">Most urgent here</div>', unsafe_allow_html=True)
                    site_items = sort_items(by_fac.get(focus, []), "Highest priority")[:4]
                    if not site_items:
                        st.markdown('<div class="group"><div class="empty">Nothing flagged here in this period.</div></div>',
                                    unsafe_allow_html=True)
                    for r in site_items:
                        a, b = st.columns([4, 1.4], vertical_alignment="center")
                        a.markdown(f'<div class="r-title" style="white-space:normal;font-size:14px">{esc(title_of(r)[:80])}</div>'
                                   f'<div class="r-sub">{PRIORITY_LABEL[r["tier"]]} · {esc(STATUS_LABEL.get(r["status"], r["status"]))}</div>',
                                   unsafe_allow_html=True)
                        b.button("Open", key=f"sh_{r['id']}", on_click=_open_hit, args=(r["id"],))
                else:
                    shown = [f for f in ranked if stats[f]["items"]] or ranked[:8]
                    quiet = len(FACS) - len([f for f in ranked if stats[f]["items"]])
                    st.markdown(f'<div class="sheet"><div class="sheet-title">Sites</div>'
                                f'<div class="sheet-sub">Last {days} d · {quiet} quiet</div></div>', unsafe_allow_html=True)
                    for fid in shown:
                        s = stats[fid]
                        ev = events_by_fac.get(fid)
                        sub = (f'{s["open"]} open · {s["top"].lower()}' if s["items"] else "Quiet")
                        if ev:
                            sub = f'Event {t_local(ev[0]["start_at"], "%a %-I %p")} · ' + sub
                        a, b = st.columns([5, 1.2], vertical_alignment="center")
                        a.markdown(f'<div class="row" style="padding:6px 2px"><span class="dot" style="background:{STATUS[s["tier"]]}">'
                                   f'</span><div class="r-main"><div class="r-title">{esc(short(fid))} '
                                   f'<span style="color:{SECONDARY};font-weight:500">{s["max"] or ""}</span></div>'
                                   f'<div class="r-sub">{esc(sub)}</div></div></div>', unsafe_allow_html=True)
                        b.button("›", key=f"site_{fid}", help=f"Zoom to {short(fid)}", on_click=_focus, args=(fid,))
            with st.container(key="legend"):
                legend = [("Act now", STATUS["ACT"]), ("Alert", STATUS["ALERT"]), ("Watch", STATUS["WATCH"]), ("Quiet", STATUS["NONE"])]
                legend += [(n, c) for n, c, layer in [("Event", BLUE, "Events"), ("Aircraft", PURPLE, "Aircraft"),
                                                      ("Vessel", CYAN, "Vessels"), ("Police incident", INDIGO, "Police incidents"),
                                                      ("Traffic", YELLOW, "Traffic")] if layer in layers_on]
                st.markdown('<div class="legend">' + "".join(f'<span style="--c:{c}">{n}</span>' for n, c in legend) + "</div>",
                            unsafe_allow_html=True)
        if focus or "3D" in view_opts:
            st.button("Reset view", key="map_reset", on_click=_reset_map)

    # ---- events · context
    e1, e2 = st.columns([1.55, 1], gap="medium")
    with e1, st.container(key="card_events"):
        evs = [e for e in upcoming if not focus or e["facility_id"] == focus]
        st.markdown(f'<div class="c-head"><span class="c-title">Upcoming events</span><span class="c-sub">'
                    f'next 14 days · {len(evs)}</span></div>', unsafe_allow_html=True)
        if evs:
            def ev_row(e):
                link = (f'<a class="open" href="{esc(e["url"])}" target="_blank">Details</a>' if has_link(e["url"]) else "")
                return (f'<div class="row"><div class="cal"><div class="m">{t_local(e["start_at"], "%b")}</div>'
                        f'<div class="d">{t_local(e["start_at"], "%-d")}</div></div><div class="r-main">'
                        f'<div class="r-title">{esc(e["name"])}</div><div class="r-sub">{esc(short(e["facility_id"]))}, '
                        f'{t_local(e["start_at"], "%a %-I:%M %p")} ET, {esc(e["source"])}</div></div>{link}</div>')
            with st.container(height=min(70 * len(evs) + 4, 290), border=False):
                st.markdown('<div class="group">' + "".join(ev_row(e) for e in evs) + "</div>", unsafe_allow_html=True)
        else:
            st.markdown('<div class="empty">No events in the next 14 days.</div>', unsafe_allow_html=True)
    with e2, st.container(key="card_context"):
        st.markdown('<div class="c-title">Context</div>', unsafe_allow_html=True)
        low_air = sum(1 for t in store.tracks_since("aircraft", now - timedelta(hours=3))
                      if isinstance(json.loads(t["info"]).get("alt"), (int, float)) and json.loads(t["info"])["alt"] <= 2000)
        sens = [(PURPLE, "Aircraft", f"{low_air} below 2,000 ft · last 3 h",
                 len(store.tracks_since("aircraft", now - timedelta(hours=3)))),
                (CYAN, "Vessels", "Last 6 h", len(store.tracks_since("vessel", now - timedelta(hours=6)))),
                (INDIGO, "Police incidents at sites", f"Last {days} d", len(store.geo_posts(("opendata",), start))),
                (YELLOW, "Traffic near sites", f"Last {days} d", len(store.geo_posts(("ny511",), start)))]
        st.markdown('<div class="group">' + "".join(
            f'<div class="row"><span class="dot" style="background:{c}"></span><div class="r-main">'
            f'<div class="r-title">{t}</div><div class="r-sub" style="white-space:normal">{s}</div></div><div class="r-trail">{n}</div></div>'
            for c, t, s, n in sens) + "</div>", unsafe_allow_html=True)


# ================================================================== INCIDENTS
with tab_inc:
    f1, f2, f3, f4 = st.columns([2, 1.3, 1.3, 1.3])
    q = f1.text_input("Search", placeholder="Search text, source or site", key="inc_q")
    sites_sel = f2.multiselect("Sites", sorted({r["facility_id"] for r in rows}, key=short), format_func=short, key="inc_sites")
    status_view = f3.selectbox("Status", ["Needs attention", "All"] + [STATUS_LABEL[s] for s in STATUSES], key="inc_status")
    inc_sort = f4.selectbox("Sort", ["Highest priority", "Most recent", "Oldest unresolved", "Lowest confidence",
                                     "Most corroborated"], key="inc_sort")
    view = st.segmented_control("View", ["Cards", "Table"], default="Cards", key="inc_view") or "Cards"
    show_inactive = status_view in (STATUS_LABEL["false_positive"], STATUS_LABEL["duplicate"], "All")
    pool = [dict(r) for r in store.hits_between(start, end, min_tier, include_dismissed=show_inactive)]
    pool = [r for r in pool if (not cat_filter or set(json.loads(r["categories"])) & set(cat_filter))
            and (not src_filter or r["source_name"] in src_filter)]
    if q:
        ql = q.lower()
        pool = [r for r in pool if ql in (r["text"] or "").lower() or ql in r["source_name"].lower()
                or ql in matcher.facility_name(r["facility_id"]).lower()]
    if sites_sel:
        pool = [r for r in pool if r["facility_id"] in sites_sel]
    if status_view == "Needs attention":
        pool = [r for r in pool if r["status"] in OPEN]
    elif status_view != "All":
        code = next(k for k, v in STATUS_LABEL.items() if v == status_view and k in STATUSES)
        pool = [r for r in pool if r["status"] == code or (code == "false_positive" and r["status"] == "dismissed")
                or (code == "in_review" and r["status"] == "reviewed")]
    pool = sort_items(pool, inc_sort)
    if view == "Cards":
        pool = intel.collapse(pool)   # one card per report, listing every site it names
    st.caption(f"{len(pool)} item{'s' if len(pool) != 1 else ''} · last {days} d · {level}")
    if not pool:
        st.info("Nothing matches these filters.")
    elif view == "Cards":
        page_n = max(1, (len(pool) + 24) // 25)
        page = st.number_input("Page", 1, page_n, 1, key="inc_page") if page_n > 1 else 1
        for r in pool[(page - 1) * 25: page * 25]:
            incident_card(r, "inc")
    else:
        data = [{"id": r["id"], "priority": PRIORITY_LABEL[r["tier"]], "score": r["score"], "rating": r["admiralty"],
                 "site": short(r["facility_id"]), "category": ", ".join(matcher.label(c) for c in json.loads(r["categories"])),
                 "reported (ET)": t_local(r["created_at"]), "source": r["source_name"], "text": r["text"][:300],
                 "link": r["url"] if has_link(r["url"]) else None,
                 "status": r["status"] if r["status"] in STATUSES else ("in_review" if r["status"] == "reviewed" else "false_positive"),
                 "note": r["analyst_note"]} for r in pool]
        df = pd.DataFrame(data)
        edited = st.data_editor(
            df, hide_index=True, width="stretch", height=560, disabled=[c for c in df.columns if c not in ("status", "note")],
            column_config={"id": None, "link": st.column_config.LinkColumn("link", display_text="Open"),
                           "status": st.column_config.SelectboxColumn(options=STATUSES),
                           "score": st.column_config.ProgressColumn("priority score", min_value=0, max_value=100, format="%d"),
                           "text": st.column_config.TextColumn(width="large")})
        if st.button("Save changes", type="primary", key="save_table"):
            n = 0
            for (_, before), (_, after) in zip(df.iterrows(), edited.iterrows()):
                if before["status"] != after["status"] or before["note"] != after["note"]:
                    store.update_hit(int(after["id"]), status=after["status"], note=after["note"])
                    n += 1
            if mode == "Live" and n:
                try:
                    from threatwatch.export import write_excel
                    write_excel(store, matcher)
                except Exception as e:
                    st.session_state["flash_error"] = f"Excel log not updated: {e}"
            st.session_state["flash"] = f"Saved {n} change{'s' if n != 1 else ''}"
            st.rerun()

# ================================================================== FACILITIES
with tab_fac:
    ranked = sorted(FACS, key=lambda f: (-stats[f]["max"], -stats[f]["items"], short(f)))
    default = st.session_state.get("focus") if st.session_state.get("focus") in FACS else ranked[0]
    fid = st.selectbox("Site", ranked, index=ranked.index(default), format_func=lambda f: FACS[f]["name"], key="fac_pick")
    F = FACS[fid]
    S = intel.facility_summary(store, matcher, fid, now)
    st_tier = top_tier(S["open"])
    assessment = {"ACT": "Act now", "ALERT": "Needs attention now", "WATCH": "Monitoring required", "LOG": "Monitoring", "NONE": "No open items"}[st_tier]
    st.markdown(f'<div class="h2" style="margin-top:6px">{esc(F["name"])}</div><div class="lt-sub">{esc(F.get("address", ""))} · '
                f'priority {F.get("priority", 3)} site · geofence {F.get("radius_km", .5)} km</div>', unsafe_allow_html=True)
    st.markdown('<div class="strip">' + "".join(
        f'<div><div class="k">{k}</div><div class="v" style="{st_style}">{v}<small>{n}</small></div></div>' for k, v, n, st_style in [
            ("Current assessment", assessment, "", f"font-size:18px;line-height:1.3;padding-top:6px;color:{STATUS[st_tier]}"),
            ("Open items", len(S["open"]), "Alert or Watch", ""),
            ("Last 24 h", len(S["last24"]), "flagged", ""),
            ("Last 7 days", len(S["cur7"]), "flagged", ""),
            ("Reviewed", S["reviewed"], "all time", "")]) + "</div>", unsafe_allow_html=True)
    obs, interp, unk = intel.facility_narrative(S)
    st.markdown(f'<div class="brief"><h4>Observation</h4><p>{esc(obs)}</p><h4>Interpretation</h4><p>{esc(interp)}</p>'
                f'<h4>Unknown</h4><p>{esc(unk)}</p></div>', unsafe_allow_html=True)

    b1, b2, b3 = st.columns(3)
    if b1.button("Generate facility report", key="fac_report"):
        from threatwatch.report import build_report
        st.session_state["fac_report_path"] = build_report("facility", store=store, days=14, facility_ids=[fid])
    fp = st.session_state.get("fac_report_path")
    if fp and Path(fp).exists() and fid in Path(fp).name:
        b1.download_button("Download facility report", Path(fp).read_bytes(), file_name=Path(fp).name, on_click="ignore",
                           mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    if b2.button("Show on map", key="fac_map"):
        st.session_state["focus"] = fid
        st.session_state["flash"] = "Focused on the Dashboard map"
        st.rerun()

    c1, c2 = st.columns([1.5, 1], gap="large")
    with c1:
        st.markdown('<div class="col-title">Open items</div>', unsafe_allow_html=True)
        if not S["open"]:
            st.markdown('<div class="group"><div class="empty">No open Alert or Watch items.</div></div>', unsafe_allow_html=True)
        for r in sort_items(S["open"], "Highest priority")[:10]:
            incident_card(r, "fac")
        st.markdown('<div class="col-title">Categories, last 7 days</div>', unsafe_allow_html=True)
        if S["categories"]:
            mx = S["categories"][0][1]
            st.markdown('<div class="card bars">' + "".join(
                f'<div class="b-row"><span>{esc(c)}</span><div class="track"><div class="fill" style="width:{100 * n / mx:.0f}%;'
                f'background:{BLUE}"></div></div><span class="num" style="text-align:right">{n}</span></div>'
                for c, n in S["categories"]) + "</div>", unsafe_allow_html=True)
        else:
            st.markdown('<div class="group"><div class="empty">Nothing in the last 7 days.</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="col-title">Upcoming events, 14 days</div>', unsafe_allow_html=True)
        st.markdown('<div class="group">' + ("".join(
            f'<div class="row"><div class="cal"><div class="m">{t_local(e["start_at"], "%b")}</div><div class="d">'
            f'{t_local(e["start_at"], "%-d")}</div></div><div class="r-main"><div class="r-title">{esc(e["name"])}</div>'
            f'<div class="r-sub">{t_local(e["start_at"], "%a %-I:%M %p")} ET · {esc(e["source"])}</div></div></div>'
            for e in S["events"]) or '<div class="empty">None scheduled.</div>') + "</div>", unsafe_allow_html=True)
        st.markdown('<div class="col-title">Review outcomes</div>', unsafe_allow_html=True)
        st.markdown('<div class="group">' + ("".join(
            f'<div class="row"><div class="r-main"><div class="r-title">{esc(k)}</div></div><div class="r-trail">{v}</div></div>'
            for k, v in sorted(S["outcomes"].items(), key=lambda kv: -kv[1])) or '<div class="empty">Nothing reviewed yet.</div>')
            + "</div>", unsafe_allow_html=True)
        st.markdown('<div class="col-title">Nearby public-safety context, 7 days</div>', unsafe_allow_html=True)
        st.markdown('<div class="group">' + ("".join(
            f'<div class="row"><span class="dot" style="background:{INDIGO if p["source"] == "opendata" else YELLOW}"></span>'
            f'<div class="r-main"><div class="r-title">{esc(title_of(p)[:70])}</div><div class="r-sub">'
            f'{p["km"]:.1f} km away · {t_local(p["created_at"])}</div></div></div>' for p in S["nearby"])
            or '<div class="empty">No police or traffic records within 2 km.</div>') + "</div>", unsafe_allow_html=True)
        st.caption("Context only.")
        rel_src = {"keybank_center": ["schedules", "events"], "highmark_stadium": ["schedules", "events"],
                   "outer_harbor": ["ais", "nws"], "canalside": ["ais"], "naval_park": ["ais"], "intl_rail_bridge": ["ais", "ny511"]}
        names = ["news", "opendata", "ny511", "adsb"] + rel_src.get(fid, [])
        st.markdown('<div class="col-title">Source freshness for this site</div>', unsafe_allow_html=True)
        st.markdown('<div class="group">' + "".join(
            f'<div class="row"><span class="dot" style="background:{dict(good=GREEN, warn=ORANGE, bad=RED, off=GRAY)[h["level"]]}"></span>'
            f'<div class="r-main"><div class="r-title">{esc(h["name"])}</div><div class="r-sub">{esc(h["status"])}'
            f'{(" · last success " + ago(h["last_success"])) if h["last_success"] else ""}</div></div></div>'
            for h in health if h["name"] in names) + "</div>", unsafe_allow_html=True)

# ================================================================== REPORTS
with tab_rep:
    st.markdown('<div class="h3">Build a report</div>', unsafe_allow_html=True)
    kinds = {"Executive briefing": "executive", "Analyst report": "analyst", "Facility report": "facility",
             "Selected incidents": "selected"}
    r1, r2 = st.columns(2)
    kind_lbl = r1.selectbox("Report type", list(kinds), key="rep_kind",
                            help="Executive: decisions and key uncertainties. Analyst: full evidence. "
                                 "Facility: one or more sites. Selected: only the items you pick.")
    rdays = r2.number_input("Days covered", 1, 90, 7, key="rep_days")
    r3, r4, r5 = st.columns(3)
    rfac = r3.multiselect("Sites (empty = all)", list(FACS), format_func=short, key="rep_fac")
    rstat = r4.multiselect("Statuses (empty = all but false positives)", STATUSES,
                           format_func=lambda s: STATUS_LABEL[s], key="rep_stat")
    rlevel = r5.selectbox("Lowest level included", ["Watch", "Alert", "Logged"], key="rep_level")
    rcats = st.multiselect("Categories (empty = all)", list(kw_cfg.get("categories", {})), format_func=matcher.label, key="rep_cats")
    sel_ids = None
    if kinds[kind_lbl] == "selected":
        cand = [dict(r) for r in store.hits_between(now - timedelta(days=int(rdays)), end, "LOG", include_dismissed=True)]
        sel_ids = st.multiselect("Pick incidents", [r["id"] for r in cand], key="rep_ids",
                                 format_func=lambda i: next(f'{short(r["facility_id"])}: {title_of(r)[:70]} ({PRIORITY_LABEL[r["tier"]]})'
                                                            for r in cand if r["id"] == i))
    if kinds[kind_lbl] == "facility" and not rfac:
        st.caption("Pick at least one site for a facility report.")
    if st.button("Build report", type="primary", key="rep_build",
                 disabled=(kinds[kind_lbl] == "facility" and not rfac) or (kinds[kind_lbl] == "selected" and not sel_ids)):
        from threatwatch.report import build_report
        st.session_state["report_path"] = build_report(
            kinds[kind_lbl], store=store, days=int(rdays), facility_ids=rfac or None, statuses=rstat or None,
            min_tier={"Watch": "WATCH", "Alert": "ALERT", "Logged": "LOG"}[rlevel], categories=rcats or None,
            hit_ids=sel_ids or None, demo=mode == "Demo")
    rp = st.session_state.get("report_path")
    if rp and Path(rp).exists():
        st.download_button("Download report", Path(rp).read_bytes(), file_name=Path(rp).name, on_click="ignore",
                           mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        st.caption(f"Saved to {rp}")
    st.markdown('<div class="h3" style="margin-top:28px">Excel log</div>', unsafe_allow_html=True)
    from threatwatch.export import XLSX, write_excel
    e1, e2 = st.columns([1, 3])
    if e1.button("Update Excel log", disabled=mode == "Demo"):
        st.session_state["excel_path"] = write_excel(store, matcher)
    xp = Path(st.session_state.get("excel_path") or XLSX)
    if mode == "Live" and xp.exists():
        e2.download_button("Download Excel log", xp.read_bytes(), file_name=xp.name, on_click="ignore",
                           mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        st.caption(f"Saved to {xp}")

# ================================================================== COLLECTION LOG
with tab_col:
    from threatwatch.collection import PHASES, THREAT_LEVELS, analyst_initials, headers, template_row
    from threatwatch.export import COLLECTION_XLSX, STATE_WORD as SRC_STATE, write_collection_excel
    who = analyst_initials()
    scans_l = [sc for sc in store.logged_scans(80) if sc["logged"]]
    k1, k2, k3, k4, k5 = st.columns([1.5, 1.3, 1.0, 1.75, 1.45], vertical_alignment="bottom")
    scan_opts = ["all"] + [sc["id"] for sc in scans_l]
    scan_lbl = {sc["id"]: f'{t_local(sc["finished_at"])} · {sc["logged"]} new' for sc in scans_l}
    pick = k1.selectbox("Scan", scan_opts, key="cl_scan",
                        format_func=lambda v: f"All scans · last {days} d" if v == "all" else scan_lbl[v])
    raw = store.collection(scan_id=None if pick == "all" else pick, since=start if pick == "all" else None)
    srcs_avail = sorted({r["source"] for r in raw})
    f_src = k2.multiselect("Source", srcs_avail, key="cl_src")
    f_phase = k3.selectbox("Phase", ["All"] + PHASES, key="cl_phase")
    f_lvl = k4.segmented_control("Threat level", ["All"] + THREAT_LEVELS, default="All", key="cl_lvl") or "All"
    f_q = k5.text_input("Search", placeholder="Search text or source", key="cl_q")
    rows_cl = [r for r in raw if (not f_src or r["source"] in f_src)
               and (f_phase == "All" or (r["phase"] or PHASES[0]) == f_phase)
               and (f_lvl == "All" or (r["threat_level"] or "Low") == f_lvl)
               and (not f_q or f_q.lower() in f'{r["title"]} {r["source_name"]} {r["sites"]}'.lower())]

    # per-source collection for the chosen scan (or the latest one)
    sid = pick if pick != "all" else (scans_l[0]["id"] if scans_l else None)
    if sid:
        ss = store.scan_sources(sid)
        dotc = {"ok": GREEN, "empty": GREEN, "error": RED, "not_configured": GRAY}
        st.markdown(f'<div class="c-head" style="margin:6px 0 8px"><span class="c-title">Sources this scan</span>'
                    f'<span class="c-sub">{esc(scan_lbl.get(sid, ""))}</span></div>'
                    '<div class="minis" style="grid-template-columns:repeat(auto-fill,minmax(150px,1fr))">' + "".join(
                        f'<div class="mini" style="background:{SURFACE};box-shadow:0 0 0 1px {P["HAIR"]}" '
                        f'title="{esc(x["error"] or "")}"><div class="k"><i style="background:{dotc.get(x["state"], GRAY)}"></i>'
                        f'{esc(x["source"])} · {esc(SRC_STATE.get(x["state"], x["state"]))}</div>'
                        f'<div class="v">{x["items"]}<small style="font-size:11px;color:{SECONDARY};font-weight:600"> items</small></div>'
                        f'<div class="k" style="margin-top:2px">{x["new"]} new · {x["flagged"]} flagged</div></div>' for x in ss) + "</div>",
                    unsafe_allow_html=True)

    st.markdown(f'<div class="c-head" style="margin:18px 0 6px"><span class="c-title">Collection log</span>'
                f'<span class="c-sub">{len(rows_cl)} item{"s" if len(rows_cl) != 1 else ""} · each item logged once, '
                f'when first collected · Analyst Notes, Threat Level, Initials and Phase are editable</span></div>',
                unsafe_allow_html=True)
    if not rows_cl:
        st.markdown('<div class="card empty">Nothing collected for this filter yet. It fills in with every scan.</div>',
                    unsafe_allow_html=True)
    else:
        cols_h = headers()
        df_cl = pd.DataFrame([template_row(r, who) for r in rows_cl[:3000]], columns=cols_h)
        df_cl.insert(0, "_id", [r["id"] for r in rows_cl[:3000]])
        edited_cl = st.data_editor(
            df_cl, hide_index=True, width="stretch", height=560, key=f"cl_editor_{pick}",
            disabled=[c for c in df_cl.columns if c not in (cols_h[1], cols_h[2], cols_h[9], cols_h[10])],
            column_config={
                "_id": None,
                cols_h[2]: st.column_config.SelectboxColumn(cols_h[2], options=PHASES, width="medium"),
                cols_h[5]: st.column_config.LinkColumn(cols_h[5], width="medium"),
                cols_h[8]: st.column_config.TextColumn(cols_h[8], width="large"),
                cols_h[9]: st.column_config.TextColumn(cols_h[9], width="medium"),
                cols_h[10]: st.column_config.SelectboxColumn(cols_h[10], options=THREAT_LEVELS, width="small"),
            })
        s1, s2, s3, _ = st.columns([1, 1.2, 1.2, 3])
        if s1.button("Save edits", type="primary", key="cl_save"):
            n_ch = 0
            for (_, a), (_, b) in zip(df_cl.iterrows(), edited_cl.iterrows()):
                if any(a[c] != b[c] for c in (cols_h[1], cols_h[2], cols_h[9], cols_h[10])):
                    store.update_collection(int(a["_id"]), analyst_notes=b[cols_h[9]], threat_level=b[cols_h[10]],
                                            initials=b[cols_h[1]], phase=b[cols_h[2]])
                    n_ch += 1
            try:
                write_collection_excel(store)
            except Exception as e:
                st.session_state["flash_error"] = f"Excel not updated: {e}"
            st.session_state["flash"] = f"Saved {n_ch} row{'s' if n_ch != 1 else ''}"
            st.rerun()
        s2.download_button("Download CSV", edited_cl.drop(columns=["_id"]).to_csv(index=False).encode("utf-8-sig"),
                           file_name="ThreatWatch_collection_log.csv", mime="text/csv", key="cl_csv", width="stretch")
        if s3.button("Build Excel", key="cl_xlsx", width="stretch"):
            st.session_state["cl_xlsx_path"] = write_collection_excel(store)
        if st.session_state.get("cl_xlsx_path") and Path(st.session_state["cl_xlsx_path"]).exists():
            xp_ = Path(st.session_state["cl_xlsx_path"])
            st.download_button("Download Excel", xp_.read_bytes(), file_name=xp_.name, key="cl_xlsx_dl",
                               mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        st.caption(f"Also saved after every scan: {COLLECTION_XLSX}")

# ================================================================== ADMIN
with tab_admin:
    a_src, a_rules, a_sites, a_scan = st.tabs(["Data sources", "Detection rules", "Sites & events", "Scans & alerts"])

    with a_src:
        source_setup()
        st.markdown(f'<div class="h3" style="margin-top:26px">Data health · coverage '
                    f'{"Demo" if mode == "Demo" else intel.coverage_level(health)}</div>', unsafe_allow_html=True)
        color = {"good": GREEN, "warn": ORANGE, "bad": RED, "off": GRAY}
        for h in health:
            detail = []
            if h["last_success"]:
                detail.append(f"last success {ago(h['last_success'])}")
            if h["latest_item_at"]:
                detail.append(f"newest item published {ago(h['latest_item_at'])}")
            if h["enabled"] and h["state"] in ("ok", "empty"):
                detail.append(f"{h['items']} item(s) last run")
            st.markdown(f'<div class="health"><i style="background:{color[h["level"]]}"></i><b>{esc(h["name"])}</b>'
                        f'<div><b>{esc(h["status"])}</b>{(" · " + esc(", ".join(detail))) if detail else ""}'
                        + (f'<div class="r-sub" style="white-space:normal;color:{RED}">{esc(h["error"][:220])}</div>'
                           if h["error"] and h["level"] in ("bad", "warn") else "")
                        + f'<div class="r-sub" style="white-space:normal">{esc(h["coverage"])}</div></div></div>',
                        unsafe_allow_html=True)

    with a_rules:
        st.markdown('<div class="h3">Keywords</div>', unsafe_allow_html=True)
        st.caption("Weight 1–10 = severity · 0 = context only")
        cats = kw_cfg.get("categories", {})
        new_cats: dict = {}
        for cid, c in cats.items():
            terms = c.get("terms", [])
            with st.expander(f"{c.get('label', cid)}  —  weight {c.get('weight', 0)}, {len(terms)} terms"):
                a, b = st.columns([3, 1])
                label = a.text_input("Name", c.get("label", cid), key=f"lbl_{cid}")
                weight = b.slider("Weight", 0, 10, int(c.get("weight", 0)), key=f"w_{cid}")
                keep = st.multiselect("Terms", options=terms, default=terms, key=f"t_{cid}")
                add = st.text_input("Add terms", key=f"add_{cid}", placeholder="machete, shots fired, stampede")
                if not st.checkbox("Delete this category", key=f"del_{cid}"):
                    merged = keep + [t for t in split_terms(add) if t.lower() not in {k.lower() for k in keep}]
                    new_cats[cid] = {"label": label, "weight": weight, "terms": merged}
        st.markdown("**New category**")
        n1, n2, n3 = st.columns([2, 1, 3])
        nc_label = n1.text_input("Name", key="nc_label", placeholder="Cyber and doxxing")
        nc_weight = n2.slider("Weight", 0, 10, 6, key="nc_weight")
        nc_terms = n3.text_input("Terms", key="nc_terms", placeholder="comma-separated")
        if nc_label and split_terms(nc_terms):
            new_cats[slug(nc_label)] = {"label": nc_label, "weight": nc_weight, "terms": split_terms(nc_terms)}
        if st.button("Save keywords", type="primary"):
            save_yaml(KEYWORDS_FILE, {"categories": new_cats}, KEYWORDS_HEADER)
            for k in [k for k in st.session_state if k.startswith(("add_", "nc_", "t_", "lbl_", "w_", "del_"))]:
                del st.session_state[k]
            st.session_state["flash"] = f"Saved {sum(len(c['terms']) for c in new_cats.values())} terms. They apply from the next scan."
            st.rerun()

        st.markdown('<div class="h3" style="margin-top:28px">Test the rules</div>', unsafe_allow_html=True)
        st.caption("One per line: + should flag, − should not")
        default_cases = ("+ Shots fired near Canalside after the concert, crowd running\n"
                         "+ Bomb threat called in to Buffalo City Hall\n"
                         "- Sabres outshoot Bruins 40-22 at KeyBank Center\n"
                         "- Bills fans tailgate at Highmark Stadium before kickoff")
        cases = st.text_area("Examples", st.session_state.get("rule_cases", default_cases), height=140, key="rule_cases")
        if st.button("Run test", key="run_rules"):
            from threatwatch.models import Post
            mt = Matcher(load_facilities(), load_keywords())
            out = []
            for line in [l.strip() for l in cases.splitlines() if l.strip()]:
                exp = True if line.startswith("+") else False if line.startswith("-") else None
                text = line.lstrip("+-").strip()
                m = mt.match(Post("test", "test", "x", "", text, now))
                res = "—" if exp is None else ("✓ as expected" if m.is_hit == exp else ("Missed" if exp else "False alarm"))
                out.append({"example": text, "flagged": "Yes" if m.is_hit else "No", "result": res,
                            "sites": ", ".join(short(f) for f in m.facilities),
                            "matched": "; ".join(f"{mt.label(k)}: {', '.join(v)}" for k, v in m.threat_terms.items())})
            st.session_state["rule_results"] = out
        if st.session_state.get("rule_results"):
            res = st.session_state["rule_results"]
            ok = sum(r["result"] == "✓ as expected" for r in res)
            graded = sum(r["result"] != "—" for r in res)
            st.caption(f"{ok} of {graded} graded examples behaved as expected.")
            st.dataframe(pd.DataFrame(res), hide_index=True, width="stretch")
        st.markdown('<div class="h3" style="margin-top:28px">How the rules perform on real items</div>', unsafe_allow_html=True)
        rq = intel.rule_quality(store, matcher)
        if rq:
            st.dataframe(pd.DataFrame(rq).rename(columns={"false_positive_or_duplicate": "false positive or duplicate",
                                                          "false_positive_share": "false-positive share"}),
                         hide_index=True, width="stretch")
            st.caption("From your reviews. High false-positive share → narrow that category's terms.")
        else:
            st.caption("Appears after you review some items.")

    with a_sites:
        st.markdown('<div class="h3">Sites</div>', unsafe_allow_html=True)
        st.caption("Ambiguous aliases need a Buffalo mention to match.")
        out = []
        for f in fac_cfg.get("facilities", []):
            with st.expander(f"{f['name']}  —  priority {f.get('priority', 3)}"):
                a, b, c = st.columns([3, 1, 1])
                name = a.text_input("Name", f["name"], key=f"fn_{f['id']}")
                prio = b.selectbox("Priority", [1, 2, 3], index=int(f.get("priority", 3)) - 1, key=f"fp_{f['id']}")
                radius = c.number_input("Radius (km)", 0.1, 10.0, float(f.get("radius_km", .5)), key=f"fr_{f['id']}")
                la, lo, sh = st.columns([1, 1, 1])
                lat = la.number_input("Latitude", value=float(f["lat"]), format="%.5f", key=f"flat_{f['id']}")
                lon = lo.number_input("Longitude", value=float(f["lon"]), format="%.5f", key=f"flon_{f['id']}")
                short_name = sh.text_input("Map label", f.get("short", ""), key=f"fsh_{f['id']}")
                aliases = st.multiselect("Aliases", f.get("aliases", []), f.get("aliases", []), key=f"fa_{f['id']}")
                add_a = st.text_input("Add aliases", key=f"faa_{f['id']}")
                amb = st.multiselect("Ambiguous aliases", f.get("ambiguous", []), f.get("ambiguous", []), key=f"fm_{f['id']}")
                add_m = st.text_input("Add ambiguous aliases", key=f"fma_{f['id']}")
                st.caption(f.get("address", ""))
                out.append({**f, "name": name, "short": short_name, "priority": prio, "radius_km": radius, "lat": lat,
                            "lon": lon, "aliases": aliases + split_terms(add_a), "ambiguous": amb + split_terms(add_m)})
        if st.button("Save sites", type="primary"):
            save_yaml(FACILITIES_FILE, {"context_terms": fac_cfg.get("context_terms", []), "facilities": out}, FACILITIES_HEADER)
            st.session_state["flash"] = "Sites saved"
            st.rerun()

        st.markdown('<div class="h3" style="margin-top:28px">Events</div>', unsafe_allow_html=True)
        st.caption("Times in ET. Sabres and Bills home games load automatically.")
        from threatwatch.collectors.schedules import EVENTS_FILE
        import yaml as _yaml
        try:
            manual = (_yaml.safe_load(EVENTS_FILE.read_text(encoding="utf-8")) or {}).get("events", []) or []
        except FileNotFoundError:
            manual = []
        site_ids = [f["id"] for f in fac_cfg.get("facilities", [])]
        edf = pd.DataFrame([{"name": e.get("name", ""), "site": e.get("site", site_ids[0]), "start": str(e.get("start", "")),
                             "url": e.get("url", "")} for e in manual] or [], columns=["name", "site", "start", "url"])
        ev_edit = st.data_editor(edf, num_rows="dynamic", hide_index=True, width="stretch", key="events_editor",
                                 column_config={"name": st.column_config.TextColumn("Event", required=True),
                                                "site": st.column_config.SelectboxColumn("Site", options=site_ids, required=True),
                                                "start": st.column_config.TextColumn("Starts (YYYY-MM-DD HH:MM, ET)", required=True),
                                                "url": st.column_config.LinkColumn("Link (optional)")})
        if st.button("Save events", type="primary"):
            good, bad = [], []
            for _, row in ev_edit.iterrows():
                if not str(row.get("name") or "").strip():
                    continue
                try:
                    datetime.strptime(str(row["start"]).strip(), "%Y-%m-%d %H:%M")
                except ValueError:
                    bad.append(str(row["name"]))
                    continue
                item = {"name": str(row["name"]).strip(), "site": row["site"], "start": str(row["start"]).strip()}
                if str(row.get("url") or "").startswith("http"):
                    item["url"] = str(row["url"])
                good.append(item)
            if bad:
                st.error("Start time must look like 2026-10-25 19:00 for: " + ", ".join(bad))
            else:
                EVENTS_FILE.write_text("# Events you add yourself. Edited from the dashboard (Admin > Sites & events).\n"
                                       + _yaml.safe_dump({"events": good}, sort_keys=False, allow_unicode=True), encoding="utf-8")
                from threatwatch.collectors.schedules import load_manual
                store.conn.execute("DELETE FROM events WHERE source='Manual'")
                for e in load_manual(fac_cfg.get("facilities", [])):
                    store.upsert_event(e)
                store.commit()
                st.session_state["flash"] = f"Saved {len(good)} event{'s' if len(good) != 1 else ''}"
                st.rerun()

    with a_scan:
        from threatwatch.collection import analyst_initials
        n1, n2, _ = st.columns([2, 1, 3])
        nm = n1.text_input("Your name (shown in the greeting)", value=load_ui().get("name") or "Nate", key="ui_name")
        ini = n2.text_input("Analyst initials (collection log)", value=analyst_initials(), key="ui_initials", max_chars=5)
        if nm and nm != (load_ui().get("name") or "Nate"):
            save_ui(name=nm.strip()[:40])
            st.rerun()
        if ini and ini.upper() != analyst_initials():
            save_ui(initials=ini.strip().upper()[:5])
            st.rerun()
        if mode == "Demo":
            st.info("You're looking at demo data. Switch the sidebar to Live to run real scans.")
        a, c = st.columns(2, gap="large")
        with a:
            st.markdown('<div class="h3">Scan now</div>', unsafe_allow_html=True)
            send_alerts = st.toggle("Send alerts", True)
            if st.button("Run scan", type="primary", disabled=mode == "Demo"):
                do_scan(send_alerts=send_alerts)
                st.rerun()
            scan_feedback("admin")
            res = st.session_state.get("scan_result") or {}
            for k, v in (res.get("errors") or {}).items():
                st.error(f"{k}: {v}")
        with c:
            st.markdown('<div class="h3">Alerts</div>', unsafe_allow_html=True)
            if st.button("Send test alert"):
                from threatwatch.alerts import send
                ok, errs = send("ThreatWatch test alert", [{
                    "facility": "Test", "score": 0, "admiralty": "—", "categories": "Test", "terms": "test",
                    "source": "ThreatWatch", "time": "now", "corroborating": 0,
                    "text": "Alert delivery works.", "url": "https://github.com/"}])
                st.write(f"Delivered on {ok} channel{'s' if ok != 1 else ''}")
                for e in errs:
                    st.error(e)
            from threatwatch.alerts import summary_enabled
            on, why = summary_enabled()
            st.caption("Summary email: " + ("on" if on else f"off — {why}"))
        st.markdown('<div class="h2">Recent scans</div>', unsafe_allow_html=True)
        recent = store.recent_scans(20)
        if recent:
            st.dataframe(pd.DataFrame([{"finished (ET)": t_local(s["finished_at"]), "collected": s["collected"],
                                        "new": s["new_posts"], "flagged": s["hits"], "alerts": s["alerts"],
                                        "errors": ", ".join(json.loads(s["errors"] or "{}").keys())} for s in recent]),
                         hide_index=True, width="stretch")
        else:
            st.caption("No scans yet.")

# ------------------------------------------------------------------ open incident (one dialog per run)
if st.session_state.get("open_hit"):
    incident_dialog(st.session_state["open_hit"])
