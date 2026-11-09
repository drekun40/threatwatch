# ThreatWatch — Buffalo facility threat monitor

Watches 27 Buffalo and Erie County sites across open sources and sensor feeds. Each item is scored, rated with the Admiralty system and placed on a live map. Alerts go to Teams or email, and a Word report is built each week.

```
Google + Bing News · GDELT · 8 local outlet feeds                (what's published)
Bluesky · Mastodon · Telegram · YouTube                          (what people post)
NWS alerts · FAA flight restrictions                             (official notices)
Open Data Buffalo police incidents · 511NY traffic events        (official records)
ADS-B aircraft · AIS vessels                                     (sensors)
Ticketmaster events                                              (crowd context)
        → dedupe → match site (by name or location) + threat keywords
        → score 0–100 + rating → Act now / Alert / Watch / Logged
        → map dashboard · Teams/email alerts · summary email per scan · Excel log · weekly .docx
```

## 1. Install (once)

You need Python 3.10 or newer.

```bash
cd threatwatch
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
streamlit run app.py        # opens the dashboard; switch the sidebar to Demo to explore
```

## 2. Connect the sources

The easiest way: **Admin → Data sources → Connect sources**. Open a source, follow its "Get a key" link, paste the key, and press **Save & test**. The same page sets up email and lets you edit the free feeds, searches and hashtags. Or edit `.env` by hand:

Open `.env` and add the keys you have. Every key is free. Then run:

```bash
python run.py selftest      # connects to every source and reports what it found or how to fix it
```

| Source | What it adds | Key | Get it |
|---|---|---|---|
| Google News + Bing News | Searches per site plus threat sweeps ("bomb threat" … Buffalo / Erie County); Bing links go straight to the publisher | none | — |
| Local outlet feeds | WGRZ, WKBW, WIVB, Spectrum News, Investigative Post, Buffalo Rising | none | — |
| GDELT | Global news index updated every 15 min: national, trade and international outlets | none | — |
| FAA TFRs | Temporary flight restrictions over the Buffalo area (VIP visits, security) | none | — |
| Mastodon | Public posts with Buffalo hashtags | none | — |
| NWS alerts | Weather, gale, visibility, lake effect | none | — |
| Open Data Buffalo | BPD incidents inside site geofences (published with a lag of a day or more) | none (optional `SOCRATA_APP_TOKEN`) | data.buffalony.gov |
| ADS-B | Aircraft and helicopters below 2,000 ft over sites, excluding BUF airport traffic | none | — |
| 511NY | Crashes, closures and incidents near sites | `NY511_API_KEY` | 511ny.org/developers |
| Ticketmaster | Games and concerts at venues; threat items near an event get +5 | `TICKETMASTER_API_KEY` | developer.ticketmaster.com |
| YouTube | Videos and livestreams geotagged near sites, plus keyword searches | `YOUTUBE_API_KEY` | Google Cloud console → enable YouTube Data API v3 → API key |
| AIS | Vessels on the waterfront: aground, stationary at the rail bridge, speeding in the harbor | `AISSTREAM_API_KEY` | aisstream.io (sign in with GitHub) |
| Telegram | Public channels you choose | `TELEGRAM_API_ID`, `TELEGRAM_API_HASH` | my.telegram.org → API development tools |
| Bluesky | Public posts | `BLUESKY_HANDLE`, `BLUESKY_APP_PASSWORD` | Bluesky → Settings → App passwords |
| Reddit | Local subreddits | after approval | Reddit's Responsible Builder Policy |
| X | Posts (pay-per-use) | `X_BEARER_TOKEN` | developer.x.com |

**Telegram** needs two extra steps. Run `python run.py telegram-login` once and enter the code Telegram sends you. Then list the channels you want in `config/sources.yaml`:

```yaml
  telegram:
    channels:
      - {username: somelocalnewschannel, reliability: C, local: true}
```

The account only reads. It never posts, and it never joins anything.

A source that is enabled but has no key shows as "set up" in the sidebar and is skipped. It never breaks a scan.

**Alerts:** set `ALERT_CHANNELS=email` (or `teams,email`) and fill in the SMTP or Teams fields. Check them with `python run.py test-alert`.

Two kinds of message go out:
- **Alert messages:** Act now and Alert items, sent once each through every channel as soon as a scan finds them.
- **Scan summary email:** one email after every scan, including scans that find nothing. It has collected and new counts, items by level, counts per source, errors, sources not set up, and the top 10 Act/Alert/Watch items with links. It's sent when `email` is in `ALERT_CHANNELS`, the SMTP fields and `ALERT_EMAIL_TO` are filled in, and `SCAN_SUMMARY_EMAIL=1` (the default). Set `SCAN_SUMMARY_EMAIL=0` to stop it. Scans run with alerts turned off (`scan --no-alerts`, or the toggle in Admin) send neither kind. With the hourly schedule, expect a summary at 07:00 and 15:00, plus one per hour around events and after alerts.

After a dashboard scan, a **Last scan** card shows counts by level, whether alert and summary delivery worked (or why they were skipped), source problems, and sources not set up.

## 3. Daily use

| Command | What it does |
|---|---|
| `streamlit run app.py` | Dashboard: map, review queue, keywords, sites, scans and reports |
| `python run.py scan` | One scan from the command line |
| `python run.py report` | Weekly Word report → `reports/` |
| `python run.py selftest -v` | Live source check with sample items |
| `python run.py rescore` | Re-apply current keywords and filters to unreviewed items |
| `python run.py test-alert` | Test message on every channel, plus a test summary email |
| `python run.py demo` | Rebuild the demo data |

**Dashboard** (start here every morning)
- **Daily briefing:** high-priority count, items awaiting review, sites needing attention, corroborated items and data coverage. Below that, three short statements generated from your data: *what the data shows*, *what it may mean*, and *what we don't know*.
- **Priority actions** (top open items), **notable changes** (last 24 h vs the 24 h before, always with the counts, and "not enough history" until 48 h of scans exist) and **monitoring gaps** (sources that are down or not set up, which are blind spots, not quiet).
- **Map** with a time window (Latest, 6 h, 24 h, 7 d) and layers. Click a report pin to open it, click a site to zoom in, click any other marker to see it in the side panel. **3D** shows each site's top score as a column. Aircraft and vessels are positions from the last scan, not live tracks.
- **Priority queue:** one card per report (a report naming two sites lists both), sortable by priority, recency, oldest unresolved, lowest confidence or most corroborated.

**Appearance:** Light or Dark in the sidebar. The whole dashboard switches, including the map (dark basemap), charts, tables, dropdowns and dialogs. The choice is remembered in `data/ui.json`. Word reports and the Excel log stay light so they print cleanly.

**Incidents:** search and filter every item; cards or a bulk-edit table. *Review* opens the incident:
- what was reported, with source time and collection time
- why it was flagged, as a score breakdown that adds up to the priority score (a review-urgency ranking, not a probability)
- how far to trust it: source reliability and information credibility, kept separate
- possibly related reports, with repeat coverage from the same outlet labeled (not independent confirmation)
- your assessment: disposition (New, In review, Confirmed, Unsubstantiated, False positive, Duplicate, Closed), your confidence, evidence and follow-up

Every change is kept in the review history.

**Facilities:** one workspace per site. It shows the current assessment, open items, the last 7 days vs the 7 before, categories, review outcomes, upcoming events, and nearby police and traffic records (context only). Each site has its own freshness check for the sources that cover it, and a one-click facility report.

**Reports:** Executive briefing, Analyst report, Facility report, or a report from incidents you pick. Filter by sites, statuses, level and categories. Every report states when it was generated and which sources were working. The Excel log is here too.

**Admin**
- **Data sources:** health per source, showing working, working with no new items, not reachable, or not set up, plus last success, newest item and coverage limits.
- **Detection rules:** the keyword editor, a rule test bench (lines starting with + should be flagged, - should not), and per-category false-positive rates from your reviews.
- **Sites & events:** site settings and your own events.
- **Scans & alerts:** run a scan, test alerts, see scan history.

## 4. Schedule

The Mac installer schedules `run.py scan --auto` every hour. It does a full scan at 07:00 and 15:00, and in other hours it only scans when something is happening:
- from 6 h before until 3 h after a scheduled event at a site (games, concerts, your own events)
- for 6 h after an open alert

Quiet hours are skipped in about a second. All of this is set in the `scan:` block of `config/sources.yaml`. All sources run in parallel, so a full scan takes about a minute (a source that hangs is skipped after `max_seconds`).

Other systems:

Windows Task Scheduler: Program `C:\path\to\threatwatch\.venv\Scripts\python.exe`, Arguments `run.py scan`, Start in `C:\path\to\threatwatch`. Arguments `run.py scan --auto`, trigger hourly. Add a weekly task with Arguments `run.py report`.

macOS/Linux cron:
```
0 * * * *     cd /path/to/threatwatch && .venv/bin/python run.py scan --auto >> data/cron.log 2>&1
30 7 * * MON  cd /path/to/threatwatch && .venv/bin/python run.py report >> data/cron.log 2>&1
```

Aircraft and vessel positions are snapshots taken at scan time, which is why event windows scan hourly.

## 5. Scoring

The priority score (0–100) ranks items for review. It is **not** a probability. Every item's factors are listed in the incident view and always add up to the score.

| Factor | Points |
|---|---|
| Severity: highest category weight × 6 | 0–60 |
| Each extra threat category | +5 (max +10) |
| Context term (concert, waterfront, Bills game…) | +5 |
| Site priority 1 / 2 / 3 | +10 / +5 / 0 (Buffalo-area-only: −5) |
| Source reliability A / B / C / D / E–F | +10 / +5 / 0 / −5 / −10 |
| Each independent corroborating source within 12 h | +10 (max +20) |
| Scheduled event at that venue within ±6 h | +5 |
| Under 3 hours old | +5 |
| Wording reads as past, legal or non-live coverage (`config/filters.yaml`) | −15 |

`score = clamp(sum, 0, 100)`. The level comes from `tier_for()` in `threatwatch/scoring.py`, with thresholds under `tiers:` in `config/sources.yaml`:

| Level | Rule | What happens |
|---|---|---|
| **Act now** (Priority 0) | score ≥ `act` (85) **and** a monitored site **and** (≥ 1 independent corroborating source **or** source reliability in `act_reliability`, default A/B) | Sent immediately, listed first, marked "ACT NOW" in the subject |
| **Alert** (Priority 1) | score ≥ `alert` (70) at a monitored site | Sent immediately |
| **Watch** (Priority 2) | score ≥ `watch` (40) | Analyst queue, Excel log, reports |
| **Logged** (Priority 3) | below 40 | Kept for search and patterns |

Items that name Buffalo but no monitored site are capped: Logged if the top category weight is below 9, otherwise Watch at most (never Alert or Act now). A high score from a single unverified source stays at Alert, so Act now always has either corroboration or a trusted source.

The rating is a source letter plus a credibility number:
- **Source:** A official record or sensor, B established media, C known account, D unverified social.
- **Credibility:** 2 = corroborated by 2+ sources, 3 = by one, 4 = uncorroborated, 1 = analyst-confirmed.

Located items (police incidents, traffic events, aircraft, vessels) match the nearest site whose geofence contains them. Text items match by site name or alias.

**Collection reliability:** every HTTP request from a collector is retried up to 3 times with a short backoff (0.8 s, then 1.6 s) on connection errors, timeouts and HTTP 500/502/503/504. Rate limits (429) aren't retried; GDELT pauses itself for 45 minutes instead. A source that still fails is marked "not reachable" and the rest of the scan continues.

## 6. Limits to keep in mind

- Consumer drones don't broadcast ADS-B. Detecting drones on site needs a Remote ID receiver.
- Many small boats carry no AIS. No vessels on the map does not mean the water is clear.
- BPD Open Data is preliminary and lags by a day or more. Use it for patterns and corroboration, not for live warning.
- 511NY's developer documentation couldn't be machine-read when this was built. The 511NY collector reads its fields and date formats tolerantly; `selftest` confirms it works with your key.
- Facility coordinates are approximate. Verify them in the Sites tab before relying on geofence matches.

## 7. Files

```
config/facilities.yaml   sites, aliases, coordinates, priority
config/keywords.yaml     threat categories and terms
config/sources.yaml      which sources run, their settings, schedule and level thresholds
config/filters.yaml      non-Buffalo "Buffalo" phrases and past/legal wording penalty
.env                     keys and alert settings (never share)
data/threatwatch.db      posts, hits, events, sensor tracks, review status (SQLite)
exports/  reports/       Excel log (ThreatWatch_alerts.xlsx) and reports
threatwatch/collectors/  one file per source
tests/                   offline tests:  python -m pytest -q
```

## 8. Guardrails

Collect public content only. Monitor sites and topics, not private individuals. Keep the database on an access-controlled machine and purge old data on a schedule. Scores are triage aids: an analyst reviews every item before it goes into a product.
