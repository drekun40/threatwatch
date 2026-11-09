"""SQLite storage: posts (deduplicated), hits, and collector state (since_ids, X read counter)."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta

from .config import DB_FILE
from .models import Hit, Post, utcnow

# Analyst dispositions. OPEN items need attention; INACTIVE items are judged not real and are left out of
# the map, the queue, corroboration and alerts (they stay in the database and the Excel log).
STATUSES = ["new", "in_review", "confirmed", "unsubstantiated", "false_positive", "duplicate", "closed"]
STATUS_LABEL = {"new": "New", "in_review": "In review", "confirmed": "Confirmed", "unsubstantiated": "Unsubstantiated",
                "false_positive": "False positive", "duplicate": "Duplicate", "closed": "Closed",
                "reviewed": "In review", "dismissed": "False positive"}       # last two: older versions
OPEN = ("new", "in_review", "reviewed")
INACTIVE = ("false_positive", "duplicate", "dismissed")
_INACTIVE_SQL = "(" + ",".join(f"'{s}'" for s in INACTIVE) + ")"

SCHEMA = """
CREATE TABLE IF NOT EXISTS posts (
    uid TEXT PRIMARY KEY,
    source TEXT, source_name TEXT, native_id TEXT, url TEXT, author TEXT,
    text TEXT, created_at TEXT, collected_at TEXT, reliability TEXT,
    is_local INTEGER, fingerprint TEXT, engagement TEXT, lat REAL, lon REAL
);
CREATE INDEX IF NOT EXISTS idx_posts_fp ON posts(fingerprint);
CREATE TABLE IF NOT EXISTS hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_uid TEXT, facility_id TEXT, categories TEXT, terms TEXT,
    score INTEGER, tier TEXT, admiralty TEXT, corroborating INTEGER,
    created_at TEXT, detected_at TEXT,
    status TEXT DEFAULT 'new',          -- new | reviewed | confirmed | dismissed
    analyst_note TEXT DEFAULT '',
    alerted INTEGER DEFAULT 0,
    UNIQUE(post_uid, facility_id)
);
CREATE INDEX IF NOT EXISTS idx_hits_fac ON hits(facility_id, created_at);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS events (            -- scheduled events at/near venues (crowd context)
    id TEXT PRIMARY KEY, source TEXT, name TEXT, venue TEXT, facility_id TEXT,
    start_at TEXT, url TEXT, lat REAL, lon REAL, info TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_fac ON events(facility_id, start_at);
CREATE TABLE IF NOT EXISTS tracks (            -- latest sensor positions: aircraft (ADS-B), vessels (AIS)
    kind TEXT, ident TEXT, name TEXT, lat REAL, lon REAL, info TEXT, seen_at TEXT,
    PRIMARY KEY (kind, ident)
);
CREATE TABLE IF NOT EXISTS review_history (     -- audit trail of every disposition / note change
    id INTEGER PRIMARY KEY AUTOINCREMENT, hit_id INTEGER, changed_at TEXT,
    old_status TEXT, new_status TEXT, note TEXT, reviewer TEXT
);
CREATE INDEX IF NOT EXISTS idx_review_hit ON review_history(hit_id);
CREATE TABLE IF NOT EXISTS source_health (      -- per-source freshness, kept across scans
    name TEXT PRIMARY KEY, state TEXT, last_attempt TEXT, last_success TEXT,
    last_items INTEGER, latest_item_at TEXT, last_error TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT, finished_at TEXT,
    collected INTEGER, new_posts INTEGER, hits INTEGER, alerts INTEGER, errors TEXT
);
CREATE TABLE IF NOT EXISTS collection_log (      -- every item every source returned, every scan
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, collected_at TEXT, source TEXT, source_name TEXT,
    post_uid TEXT, published_at TEXT, title TEXT, url TEXT, author TEXT, reliability TEXT,
    outcome TEXT,                                  -- new | already_seen | same_story
    level TEXT, sites TEXT, lat REAL, lon REAL,
    phase TEXT, tool TEXT, initials TEXT, analyst_notes TEXT, threat_level TEXT, score INTEGER
);
CREATE INDEX IF NOT EXISTS ix_collection_scan ON collection_log(scan_id);
CREATE INDEX IF NOT EXISTS ix_collection_time ON collection_log(collected_at);
CREATE TABLE IF NOT EXISTS scan_sources (        -- one row per source per scan
    scan_id INTEGER, source TEXT, state TEXT, items INTEGER, new INTEGER, flagged INTEGER,
    seconds REAL, error TEXT, PRIMARY KEY (scan_id, source)
);
"""
OUTCOME_LABEL = {"new": "New", "already_seen": "Already seen", "same_story": "Same story, other link"}


class Store:
    def __init__(self, path=DB_FILE):
        # check_same_thread=False: collectors run in parallel threads; every call from them goes
        # through LockedStore (below), so only one thread touches the connection at a time.
        self.conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        for ddl in ("ALTER TABLE scans ADD COLUMN detail TEXT",        # upgrades for older databases
                    "ALTER TABLE hits ADD COLUMN factors TEXT",
                    "ALTER TABLE hits ADD COLUMN reviewed_at TEXT"):
            try:
                self.conn.execute(ddl)
            except sqlite3.OperationalError:
                pass

    # ---- state -------------------------------------------------------------
    def get_state(self, key: str, default=None):
        row = self.conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def set_state(self, key: str, value) -> None:
        self.conn.execute("INSERT OR REPLACE INTO state(key, value) VALUES (?, ?)",
                          (key, json.dumps(value)))
        self.conn.commit()

    # ---- posts -------------------------------------------------------------
    def add_post(self, p: Post) -> bool:
        """Insert a post. Returns False if already stored or a near-duplicate of a stored post."""
        return self.add_post_status(p) == "new"

    def add_post_status(self, p: Post) -> str:
        """Insert a post; returns "new", "already_seen" (same link stored before) or "same_story" (near-duplicate)."""
        if self.conn.execute("SELECT 1 FROM posts WHERE uid=?", (p.uid,)).fetchone():
            return "already_seen"
        dup = self.conn.execute(
            "SELECT 1 FROM posts WHERE fingerprint=? AND source=?", (p.text_fingerprint, p.source)
        ).fetchone()
        if dup:
            return "same_story"
        self.conn.execute(
            "INSERT INTO posts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (p.uid, p.source, p.source_name, p.native_id, p.url, p.author, p.text,
             p.created_at.isoformat(), utcnow().isoformat(), p.reliability, int(p.is_local),
             p.text_fingerprint, json.dumps(p.engagement), p.lat, p.lon))
        return "new"

    # ---- hits --------------------------------------------------------------
    def add_hit(self, h: Hit) -> int | None:
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO hits(post_uid, facility_id, categories, terms, score, tier,
               admiralty, corroborating, created_at, detected_at, factors) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (h.post.uid, h.facility_id, json.dumps(h.categories), json.dumps(h.terms), h.score,
             h.tier, h.admiralty, h.corroborating_sources, h.post.created_at.isoformat(),
             utcnow().isoformat(), json.dumps(getattr(h, "factors", []))))
        return cur.lastrowid if cur.rowcount else None

    def corroborating_sources(self, facility_id: str, categories: list[str], source: str,
                              source_name: str, since: datetime, until: datetime | None = None) -> int:
        """Count distinct OTHER sources with a hit on the same facility + overlapping category
        whose post time falls inside [since, until]."""
        until = until or utcnow() + timedelta(days=1)
        rows = self.conn.execute(
            """SELECT DISTINCT p.source, p.source_name, h.categories FROM hits h
               JOIN posts p ON p.uid = h.post_uid
               WHERE h.facility_id=? AND h.created_at>=? AND h.created_at<=?
                 AND h.status NOT IN """ + _INACTIVE_SQL,
            (facility_id, since.isoformat(), until.isoformat())).fetchall()
        seen = set()
        for r in rows:
            if (r["source"], r["source_name"]) == (source, source_name):
                continue
            if set(json.loads(r["categories"])) & set(categories):
                seen.add((r["source"], r["source_name"]))
        return len(seen)

    def pending_alerts(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT h.*, p.source, p.source_name, p.url, p.text, p.author, p.reliability
               FROM hits h JOIN posts p ON p.uid=h.post_uid
               WHERE h.tier IN ('ACT','ALERT') AND h.alerted=0 AND h.status NOT IN """ + _INACTIVE_SQL + """
               ORDER BY h.tier='ACT' DESC, h.score DESC""").fetchall()

    def mark_alerted(self, hit_ids: list[int]) -> None:
        self.conn.executemany("UPDATE hits SET alerted=1 WHERE id=?", [(i,) for i in hit_ids])
        self.conn.commit()

    def hits_between(self, start: datetime, end: datetime, min_tier: str = "LOG",
                     include_dismissed: bool = False) -> list[sqlite3.Row]:
        from .models import tiers_at_or_above
        tiers = tiers_at_or_above(min_tier)
        q = f"""SELECT h.*, p.source, p.source_name, p.url, p.text, p.author, p.reliability, p.lat, p.lon
                FROM hits h JOIN posts p ON p.uid=h.post_uid
                WHERE h.created_at>=? AND h.created_at<? AND h.tier IN ({",".join("?"*len(tiers))})
                {"" if include_dismissed else "AND h.status NOT IN " + _INACTIVE_SQL}
                ORDER BY h.created_at DESC"""
        return self.conn.execute(q, (start.isoformat(), end.isoformat(), *tiers)).fetchall()

    def hit(self, hit_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            """SELECT h.*, p.source, p.source_name, p.url, p.text, p.author, p.reliability, p.collected_at,
                      p.fingerprint, p.lat, p.lon FROM hits h JOIN posts p ON p.uid=h.post_uid WHERE h.id=?""",
            (hit_id,)).fetchone()

    def related(self, hit_id: int, hours: float = 12) -> list[sqlite3.Row]:
        """Other reports that may describe the same event: same site, overlapping category, within ±hours.
        Each row carries same_source=1 when it comes from the same outlet (repeat coverage, not corroboration)."""
        h = self.hit(hit_id)
        if not h:
            return []
        when = datetime.fromisoformat(h["created_at"])
        rows = self.conn.execute(
            """SELECT h.*, p.source, p.source_name, p.url, p.text, p.fingerprint FROM hits h
               JOIN posts p ON p.uid=h.post_uid
               WHERE h.facility_id=? AND h.id!=? AND h.created_at BETWEEN ? AND ?
               ORDER BY h.created_at""",
            (h["facility_id"], hit_id, (when - timedelta(hours=hours)).isoformat(),
             (when + timedelta(hours=hours)).isoformat())).fetchall()
        cats = set(json.loads(h["categories"]))
        out = []
        for r in rows:
            if set(json.loads(r["categories"])) & cats:
                d = dict(r)
                d["same_source"] = int((r["source"], r["source_name"]) == (h["source"], h["source_name"]))
                out.append(d)
        return out

    def history(self, hit_id: int) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM review_history WHERE hit_id=? ORDER BY id DESC", (hit_id,)).fetchall()

    def update_hit(self, hit_id: int, status: str | None = None, note: str | None = None,
                   reviewer: str = "analyst") -> None:
        """Change disposition and/or note. Every change is written to review_history (audit trail)."""
        row = self.conn.execute("SELECT status, analyst_note FROM hits WHERE id=?", (hit_id,)).fetchone()
        if not row:
            return
        if (status is None or status == row["status"]) and (note is None or note == (row["analyst_note"] or "")):
            return
        self.conn.execute(
            "INSERT INTO review_history(hit_id, changed_at, old_status, new_status, note, reviewer) VALUES (?,?,?,?,?,?)",
            (hit_id, utcnow().isoformat(), row["status"], status or row["status"],
             note if note is not None else "", reviewer))
        self.conn.execute("UPDATE hits SET reviewed_at=? WHERE id=?", (utcnow().isoformat(), hit_id))
        if status is not None:
            self.conn.execute("UPDATE hits SET status=? WHERE id=?", (status, hit_id))
            if status == "confirmed":   # analyst confirmation -> credibility 1
                row = self.conn.execute("SELECT admiralty FROM hits WHERE id=?", (hit_id,)).fetchone()
                if row:
                    self.conn.execute("UPDATE hits SET admiralty=? WHERE id=?",
                                      (row["admiralty"][0] + "1", hit_id))
        if note is not None:
            self.conn.execute("UPDATE hits SET analyst_note=? WHERE id=?", (note, hit_id))
        self.conn.commit()

    def begin_scan(self, started) -> int:
        cur = self.conn.execute("INSERT INTO scans(started_at) VALUES (?)", (started.isoformat(),))
        self.conn.commit()
        return cur.lastrowid

    def log_scan(self, started, collected, new_posts, hits, alerts, errors, detail=None, scan_id=None) -> None:
        vals = (started.isoformat(), utcnow().isoformat(), collected, new_posts, hits, alerts,
                json.dumps(errors), json.dumps(detail or {}))
        if scan_id:
            self.conn.execute("UPDATE scans SET started_at=?, finished_at=?, collected=?, new_posts=?, hits=?, alerts=?,"
                              " errors=?, detail=? WHERE id=?", (*vals, scan_id))
        else:
            self.conn.execute("INSERT INTO scans(started_at, finished_at, collected, new_posts, hits, alerts, errors, detail)"
                              " VALUES (?,?,?,?,?,?,?,?)", vals)
        self.conn.commit()

    # ---- collection log ---------------------------------------------------------
    def log_collection(self, scan_id: int, rows: list[dict], sources: list[dict]) -> None:
        self.conn.executemany(
            "INSERT INTO collection_log(scan_id, collected_at, source, source_name, post_uid, published_at, title, url,"
            " author, reliability, outcome, level, sites, lat, lon, phase, tool, initials, analyst_notes, threat_level,"
            " score) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(scan_id, r["collected_at"], r["source"], r["source_name"], r["post_uid"], r["published_at"],
              r["title"], r["url"], r["author"], r["reliability"], r["outcome"], r["level"], r["sites"],
              r["lat"], r["lon"], r.get("phase"), r.get("tool"), r.get("initials"), r.get("analyst_notes"),
              r.get("threat_level"), r.get("score")) for r in rows])
        self.conn.executemany(
            "INSERT OR REPLACE INTO scan_sources(scan_id, source, state, items, new, flagged, seconds, error)"
            " VALUES (?,?,?,?,?,?,?,?)",
            [(scan_id, s["source"], s["state"], s["items"], s["new"], s["flagged"], s["seconds"], s["error"])
             for s in sources])
        self.conn.commit()

    def update_collection(self, row_id: int, analyst_notes: str | None = None, threat_level: str | None = None,
                          initials: str | None = None, phase: str | None = None) -> None:
        for col, val in (("analyst_notes", analyst_notes), ("threat_level", threat_level),
                         ("initials", initials), ("phase", phase)):
            if val is not None:
                self.conn.execute(f"UPDATE collection_log SET {col}=? WHERE id=?", (val, row_id))
        self.conn.commit()

    def prune_collection(self, days: int = 90) -> int:
        cut = (utcnow() - timedelta(days=days)).isoformat()
        n = self.conn.execute("DELETE FROM collection_log WHERE collected_at < ?", (cut,)).rowcount
        self.conn.execute("DELETE FROM scan_sources WHERE scan_id NOT IN (SELECT DISTINCT scan_id FROM collection_log)"
                          " AND scan_id < (SELECT COALESCE(MAX(id), 0) - 500 FROM scans)")
        self.conn.commit()
        return n

    def collection(self, scan_id: int | None = None, since: datetime | None = None, limit: int = 20000) -> list[sqlite3.Row]:
        q, args = "SELECT * FROM collection_log WHERE 1=1", []
        if scan_id:
            q += " AND scan_id=?"; args.append(scan_id)
        if since:
            q += " AND collected_at>=?"; args.append(since.isoformat())
        return self.conn.execute(q + " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()

    def scan_sources(self, scan_id: int) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM scan_sources WHERE scan_id=? ORDER BY items DESC, source", (scan_id,)).fetchall()

    def logged_scans(self, n: int = 60) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT s.*, (SELECT COUNT(*) FROM collection_log c WHERE c.scan_id=s.id) AS logged FROM scans s "
            "WHERE s.finished_at IS NOT NULL ORDER BY s.id DESC LIMIT ?", (n,)).fetchall()

    def recent_scans(self, n: int = 20):
        return self.conn.execute("SELECT * FROM scans WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT ?",
                                 (n,)).fetchall()

    # ---- events (Ticketmaster etc.) --------------------------------------------
    def upsert_event(self, e: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO events(id, source, name, venue, facility_id, start_at, url, lat, lon, info)"
            " VALUES (:id, :source, :name, :venue, :facility_id, :start_at, :url, :lat, :lon, :info)",
            {**e, "info": json.dumps(e.get("info", {}))})

    def events_between(self, start: datetime, end: datetime) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM events WHERE start_at>=? AND start_at<? ORDER BY start_at",
                                 (start.isoformat(), end.isoformat())).fetchall()

    def event_near(self, facility_id: str, when: datetime, hours: float = 6) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM events WHERE facility_id=? AND start_at BETWEEN ? AND ? ORDER BY start_at LIMIT 1",
            (facility_id, (when - timedelta(hours=hours)).isoformat(),
             (when + timedelta(hours=hours)).isoformat())).fetchone()

    # ---- tracks (ADS-B aircraft, AIS vessels) -----------------------------------
    def upsert_track(self, kind: str, ident: str, name: str, lat: float, lon: float, info: dict,
                     seen_at: datetime) -> None:
        self.conn.execute("INSERT OR REPLACE INTO tracks VALUES (?,?,?,?,?,?,?)",
                          (kind, ident, name, lat, lon, json.dumps(info), seen_at.isoformat()))

    def tracks_since(self, kind: str, since: datetime) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM tracks WHERE kind=? AND seen_at>=?",
                                 (kind, since.isoformat())).fetchall()

    def geo_posts(self, sources: tuple[str, ...], since: datetime) -> list[sqlite3.Row]:
        """Located items (police incidents, traffic events) for map layers."""
        q = f"""SELECT * FROM posts WHERE source IN ({",".join("?" * len(sources))})
                AND lat IS NOT NULL AND created_at>=? ORDER BY created_at DESC"""
        return self.conn.execute(q, (*sources, since.isoformat())).fetchall()

    # ---- source health ---------------------------------------------------------
    def record_source(self, name: str, state: str, items: int = 0, latest_item_at: str | None = None,
                      error: str = "") -> None:
        """state: ok | empty | error | not_configured. last_success only moves on ok/empty."""
        now = utcnow().isoformat()
        old = self.conn.execute("SELECT * FROM source_health WHERE name=?", (name,)).fetchone()
        last_success = now if state in ("ok", "empty") else (old["last_success"] if old else None)
        latest = latest_item_at or (old["latest_item_at"] if old else None)
        self.conn.execute("INSERT OR REPLACE INTO source_health VALUES (?,?,?,?,?,?,?)",
                          (name, state, now, last_success, items, latest, error[:400]))
        self.conn.commit()

    def source_health(self) -> dict[str, sqlite3.Row]:
        return {r["name"]: r for r in self.conn.execute("SELECT * FROM source_health").fetchall()}

    def commit(self):
        self.conn.commit()


class LockedStore:
    """Thread-safe view of a Store for collectors running in parallel: every method call
    (and every call on .conn) is serialized with one lock."""

    def __init__(self, store: Store, lock=None):
        import threading
        self._store, self._lock = store, lock or threading.RLock()

    def __getattr__(self, name):
        attr = getattr(self._store, name)
        if name == "conn":
            return LockedStore(attr, self._lock)
        if not callable(attr):
            return attr
        lock = self._lock

        def call(*a, **kw):
            with lock:
                return attr(*a, **kw)
        return call


def window_start(hours: float) -> datetime:
    return utcnow() - timedelta(hours=hours)
