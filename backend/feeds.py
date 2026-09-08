"""Local threat feeds in SQLite: sync URLhaus (and optionally PhishTank), query locally.

Keeps everything on-device: sync once a day, then all lookups are offline.
"""
import csv
import io
import sqlite3
import time
from pathlib import Path

import httpx

DB_PATH = Path(__file__).parent / "feeds.db"
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"
# PhishTank requires a (free) registered app key for its download endpoint:
# PHISHTANK_JSON = "http://data.phishtank.com/data/<your-key>/online-valid.json"

SYNC_INTERVAL_SECONDS = 24 * 3600

SCHEMA = """
CREATE TABLE IF NOT EXISTS bad_urls (
    url    TEXT PRIMARY KEY,
    domain TEXT,
    source TEXT,
    added  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_bad_domain ON bad_urls(domain);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- verdict cache for any external API you add later (e.g. Safe Browsing)
CREATE TABLE IF NOT EXISTS url_cache (
    url     TEXT PRIMARY KEY,
    verdict TEXT,
    expires INTEGER
);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    return conn


def _domain_of(url: str) -> str:
    import tldextract
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()


def sync_if_stale() -> None:
    """Call on startup and/or from a daily scheduler."""
    with _conn() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key='last_sync'").fetchone()
        last = int(row[0]) if row else 0
        if time.time() - last < SYNC_INTERVAL_SECONDS:
            return
    try:
        _sync_urlhaus()
        with _conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('last_sync', ?)",
                (str(int(time.time())),),
            )
    except Exception as exc:  # offline is fine — heuristics still work
        print(f"[feeds] sync skipped: {exc}")


def _sync_urlhaus() -> None:
    resp = httpx.get(URLHAUS_CSV, timeout=60, follow_redirects=True)
    resp.raise_for_status()
    now = int(time.time())
    rows = []
    reader = csv.reader(io.StringIO(resp.text))
    for row in reader:
        if not row or row[0].startswith("#") or len(row) < 3:
            continue
        url = row[2].strip().strip('"')
        if url.startswith("http"):
            rows.append((url, _domain_of(url), "urlhaus", now))
    with _conn() as conn:
        conn.execute("DELETE FROM bad_urls WHERE source='urlhaus'")
        conn.executemany("INSERT OR IGNORE INTO bad_urls VALUES (?,?,?,?)", rows)
    print(f"[feeds] urlhaus: loaded {len(rows)} URLs")


# Domains that host both legitimate and malicious content (free/shared
# platforms attackers abuse for phishing pages). A domain-level feed hit
# here is too broad -- one malicious Google Form poisons all of google.com,
# flagging unrelated legit links (e.g. a Google Maps link in an order
# confirmation email). Only trust an exact-URL match for these.
SHARED_HOSTING_DOMAINS = {
    "google.com", "googleusercontent.com", "drive.google.com",
    "docs.google.com", "sites.google.com", "forms.gle",
    "github.com", "github.io", "githubusercontent.com",
    "amazonaws.com", "cloudfront.net", "herokuapp.com",
    "sharepoint.com", "onedrive.live.com", "dropbox.com",
    "firebaseapp.com", "web.app", "azurewebsites.net", "pages.dev",
    "weebly.com", "wixsite.com", "blogspot.com",
    "wsimg.com", "archive.org", "myqcloud.com", "doubleclick.net",
}


def is_flagged(url: str, domain: str) -> bool:
    """Exact-URL hit always counts; domain-wide hit only for domains that
    aren't shared hosting platforms with mixed legitimate/malicious content."""
    with _conn() as conn:
        if domain in SHARED_HOSTING_DOMAINS:
            hit = conn.execute("SELECT 1 FROM bad_urls WHERE url = ? LIMIT 1", (url,)).fetchone()
        else:
            hit = conn.execute(
                "SELECT 1 FROM bad_urls WHERE url = ? OR domain = ? LIMIT 1",
                (url, domain),
            ).fetchone()
    return hit is not None
