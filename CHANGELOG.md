# Changelog

## 2026-11-09: reliability audit, wider coverage
Found by checking 102 scans of history in the database, then fixed:
- **GDELT never returned anything** (35 rate-limit errors, 33 empty runs in 68 scans): its search API now answers 429 even to the first request. It now reads GDELT's 15-minute event files instead (no rate limit, ~100 KB each), keeping threat-type events geocoded within 40 km of Buffalo. The search API stays available as `gdelt.mode: doc`.
- **Every source reported the same time** (~53 s, the slowest source's). Each source now reports its own collection time.
- **Dead feeds were invisible:** a feed that failed was only counted in a log line. Partly failed sources now carry a warning naming the failed feed (e.g. WGRZ timing out), shown in the scan output, source table and collection log.
- **Bluesky crashed on its own timestamps** (nanosecond precision, which Python 3.10 rejects). A shared `parse_iso` now reads API timestamps for Bluesky, Mastodon, X and Ticketmaster.
- **Alerts reached no one** (`ALERT_CHANNELS=console`): 3 Act now and 36 Alert items were printed to a log nobody reads. New `mac` channel: a Notification Center banner, no setup.

Wider coverage:
- **Bluesky works without a key** through the public AppView search. It had been "not set up" for every scan; the self-test now finds 169 items and 12 would-be hits over 72 h.
- **Light hourly scans** between the 07:00/15:00 full scans (371 hours had been skipped): local feeds, GDELT, NWS, TFR, Mastodon, Bluesky and ADS-B. Alerts go out; no summary email.
- **New local feeds:** The Buffalo News (local) and WBFO (NPR Buffalo).
- 11 new offline tests (79 in total).

## 2026-10-26: collection log, new sidebar, scan emails
- **Collection log in the database** (`collection_log` table) in the analyst template's 11 columns:
  - Date Collected, Analyst Initials, Collection Phase, Tool / Platform Used, Source Name, Source URL / Citation, Source Tier, Source Reliability, Raw Information, Analyst Notes, Preliminary Threat Level.
  - Every item every source returns is logged once, when first collected. A `scan_sources` table records each source on each scan: status, items returned, new, flagged, seconds, problem.
- **Collection log tab:**
  - Pick a scan or all scans, and filter by source, phase, threat level or text.
  - Per-source tiles for the scan.
  - Edit Analyst Notes, Threat Level, Initials and Phase in the table and save.
  - Download a CSV or Excel copy.
  - `exports/ThreatWatch_collection_log.xlsx` (template sheet plus "Sources per scan") is rebuilt after every scan.
- **Analyst initials** are set in Admin → Scans & alerts.
- **Scan email:** the summary after every scan now has a per-source table (status, items, new, flagged) and attaches that scan's collection log as a CSV in the template format.
- **Sidebar redesign:**
  - Controls grouped in one card, with black active segments.
  - An orange Run scan button showing the last scan and the next full scan.
  - A Sources card with ok / set-up / down counts, problems listed first.

## 2026-10-21 (late): new look
- **Card-dashboard design:** gray canvas, white rounded cards, a black pill nav, black primary buttons and an orange accent. Plus Jakarta Sans. Light and dark.
- **Header:** time-of-day greeting with your name (set it in Admin → Scans & alerts) and the Live/Demo badge.
- **Dashboard row 1:**
  - Briefing card: reports awaiting review with a 24-hour change chip, the assessment, Run scan, a one-click executive report download, and source counts.
  - Four KPI tiles; the orange one is high priority.
  - Activity chart in orange and black.
- **Row 2:**
  - Priority actions, Last 24 h and Monitoring gaps cards.
  - A Recent reports table with search, level filter, sort and an Open button on every row.
- **Then:** the map card, followed by upcoming events and context.
- **Level colors:** Act now deep red, Alert orange, Watch black (light gray in dark mode), Logged gray. They're the same on the map, chart, pills and Excel.
- Every earlier feature is kept: incident window, map clicks and 3D, source setup, keyword editor, reports, scan card.

## 2026-10-21 (night): source setup, interactive map, shorter text
- **Connect sources** (Admin → Data sources). Each key-based source has its steps, a "Get a key" link, fields to paste keys into, an on/off switch, and **Save & test**, which runs that one source live.
  - Covers Bluesky, YouTube, Ticketmaster, 511NY, AIS, Telegram (plus channel list), Open Data token, Reddit and X.
  - **Email** setup (SMTP, recipient, on/off) has a test-send button.
  - **Free sources**: switch each on or off, edit the RSS feed table, add extra news searches and Mastodon hashtags.
  - Keys are saved to `.env`. Settings go to `config/sources.local.yaml`, which overrides `sources.yaml` without touching its comments.
- **New free sources:**
  - FBI Buffalo press releases (feed)
  - NWS zones NYZ010 and NYZ019 (northern and southern Erie)
  - Mastodon instances mastodon.online and mstdn.social
- **Map:**
  - **Reports** layer: one pin per flagged report inside its site. Click a pin to open the incident.
  - Click any other marker to see it in the side panel, with a link to its source.
  - Site list rows have a › button that zooms to the site.
  - **3D** view: columns whose height is each site's top score.
  - **Large** map, and **Reset view**.
  - Aircraft link to the adsb.lol live map.
- **Shorter text:** removed explanatory captions across every tab, shortened the briefing to two lines, trimmed map tooltips, and shortened the demo banner and Admin hints.

## 2026-10-21 (evening): dark mode
- **Light/Dark switch** in the sidebar under Appearance.
- Dark mode uses Apple's dark system colors: black canvas, #1C1C1E surfaces, and the brighter dark variants of red, orange, blue and the rest.
- Streamlit's own theme switches at the same time, so tables, dropdowns, dialogs and the incident editor match the cards. The map uses CARTO's dark basemap.
- The choice is saved in `data/ui.json`, so it survives reloads and restarts.
- The activity chart and map legend now include Act now.
- "Quiet" sites use a higher-contrast gray.
- Scheduled scans wait up to 90 s for the network, and skip that hour if it doesn't come back, instead of logging an empty scan.

## 2026-10-21: summary email, Act now level, retries

**Summary email after every scan.** `alerts.send_scan_summary()` runs at the end of `run_scan`, after alerts and the Excel log. It always sends when email is set up, including scans with no hits. Subject: `ThreatWatch scan — {new} new, {alerts} alerts, {watches} watches` (with `(N ACT NOW)` when there are any). Plain-text and HTML body: counts by level, counts per source, errors, sources not set up, and the top 10 Act/Alert/Watch items with site, score, rating, text and link. It is controlled by `SCAN_SUMMARY_EMAIL` (default 1) and needs `email` in `ALERT_CHANNELS`. Per-item alert emails are unchanged. *Why: so you get a record of every scan, and you can tell a quiet scan from a scan that didn't run.*

**Delivery is reported.** `ScanResult.delivery` holds `{"alerts": {...}, "summary": {...}}`, each with `ok`, `sent` and `message`. The CLI prints both with ✓/✗. The dashboard shows a **Last scan** card (counts by level, delivery status, source problems, sources not set up) after "Run scan now" or Admin → Run scan. Admin also shows whether the summary email is on and why not. *Why: a failed SMTP login used to be visible only in the scan log.*

**Act now level (Priority 0).** Added above Alert: score ≥ 85 at a monitored site, and either corroborated or from an A/B source. Thresholds are in `sources.yaml` (`tiers.act`, `tiers.act_reliability`). Act now is sent like Alert, listed first, and flagged "ACT NOW" in the subject. It has its own deeper red in the dashboard, its own Excel fill, and its own report label. The level logic is in one pure function, `scoring.tier_for()`; `score_match()` remains the single scoring function. Shared tier constants are in `models.py` (`TIERS`, `ALERT_TIERS`, `REVIEW_TIERS`, `PRIORITY_LABEL`, `tier_rank`). Admiralty letters are unchanged. *Why: separates "high score" from "high score that's also well sourced".*

**Retries.** The new `threatwatch/http.py` gives every collector up to 3 tries with 0.8 s/1.6 s backoff on connection errors, timeouts and 5xx answers. 429 is not retried. ADS-B keeps its own fallback to a second feed, so it makes one try per feed. NotConfigured and real errors are still told apart. *Why: brief outages at local TV feeds (WGRZ timed out on the first wide scan) were marking whole sources as down.*

**Also:**
- `run.py test-alert` also sends a test summary email.
- `run.py selftest` shows the summary-email status.
- The briefing says how many alerts are Act now.

**Tests:** 64 offline tests. They cover:
- `tier_for` boundaries, including area-only caps and the Act now trust rule
- `score_match` determinism, and that the factors add up to the score
- Act now dispatched first
- summary email content (zero-hit case included), gating, and SMTP failure
- `run_scan` delivery end to end (alert, then summary, and a summary even when nothing is new)
- HTTP retry behaviour

### New keys
- `.env`: `SCAN_SUMMARY_EMAIL=1`
- `config/sources.yaml`: `tiers.act: 85`, `tiers.act_reliability: [A, B]`

## 2026-10-20: wider collection
- Bing News, threat sweeps and more local feeds.
- GDELT, FAA TFRs and Mastodon.
- Parallel collection.
- Hourly smart schedule.
- Precision filters (`config/filters.yaml`).
- `rescore` command.
