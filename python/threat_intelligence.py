#!/usr/bin/env python3
"""
threat_intelligence.py
Threat Intelligence Platform — fixed version.
All outputs are JSON on stdout so PHP's PythonBridge can parse them.

Dependencies: pip install requests
"""

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timedelta


class ThreatIntelligencePlatform:
    # Public, free IOC feeds — no API key required
    IOC_SOURCES = [
        "https://feeds.alienvault.com/alienvault_reputation.data",
        "https://rules.emergingthreats.net/blockrules/emerging-Block-IPs.txt",
        "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt",
    ]

    IP_RE     = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    DOMAIN_RE = re.compile(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    HASH_RE   = re.compile(r"^[a-fA-F0-9]{32,64}$")

    def __init__(self, db_path: str = "/tmp/aegis_threat_intel.db"):
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS indicators (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator      TEXT    UNIQUE,
                indicator_type TEXT,
                severity       TEXT    DEFAULT 'MEDIUM',
                confidence     INTEGER DEFAULT 50,
                first_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source         TEXT,
                description    TEXT
            );
            CREATE TABLE IF NOT EXISTS ioc_fetches (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                source      TEXT,
                fetched_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                count_added INTEGER DEFAULT 0
            );
        """)
        self.db.commit()

    def collect_feeds(self) -> dict:
        """Fetch IOC feeds and store new indicators.  Returns summary."""
        try:
            import requests
        except ImportError:
            return {"error": "requests not installed — run: pip install requests"}

        total_added = 0
        for source in self.IOC_SOURCES:
            try:
                resp = requests.get(source, timeout=10)
                if resp.status_code == 200:
                    added = self._process_feed(resp.text, source)
                    total_added += added
                    self.db.execute(
                        "INSERT INTO ioc_fetches (source, count_added) VALUES (?, ?)",
                        (source, added),
                    )
            except Exception as exc:
                pass  # Non-fatal: one bad feed doesn't abort the rest

        self.db.commit()
        return {"status": "ok", "total_added": total_added}

    def _process_feed(self, raw: str, source: str) -> int:
        added = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            indicator = line.split()[0]  # Some feeds have extra columns
            if self._validate_ioc(indicator):
                try:
                    self.db.execute(
                        """INSERT INTO indicators (indicator, indicator_type, source, last_seen)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT(indicator) DO UPDATE SET last_seen = excluded.last_seen""",
                        (indicator, self._detect_type(indicator), source, datetime.now()),
                    )
                    added += 1
                except Exception:
                    pass
        return added

    def _validate_ioc(self, ioc: str) -> bool:
        return bool(
            self.IP_RE.match(ioc)
            or self.DOMAIN_RE.match(ioc)
            or self.HASH_RE.match(ioc)
        )

    def _detect_type(self, ioc: str) -> str:
        if self.IP_RE.match(ioc):
            return "IP"
        if self.DOMAIN_RE.match(ioc):
            return "DOMAIN"
        if self.HASH_RE.match(ioc):
            return "HASH"
        return "UNKNOWN"

    def check_indicator(self, indicator: str) -> dict:
        row = self.db.execute(
            "SELECT * FROM indicators WHERE indicator = ?", (indicator,)
        ).fetchone()
        if row:
            return {"found": True, "data": dict(row)}
        return {"found": False}

    def summary(self) -> dict:
        total = self.db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        by_type = dict(
            self.db.execute(
                "SELECT indicator_type, COUNT(*) FROM indicators GROUP BY indicator_type"
            ).fetchall()
        )
        recent = [
            dict(r)
            for r in self.db.execute(
                "SELECT indicator, indicator_type, last_seen FROM indicators"
                " WHERE last_seen > datetime('now', '-7 days')"
                " ORDER BY last_seen DESC LIMIT 10"
            ).fetchall()
        ]
        return {
            "total_iocs": total,
            "by_type": by_type,
            "recent": recent,
            "status": "running",
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--args", default="{}")
    args = parser.parse_args()

    try:
        params = json.loads(args.args)
    except json.JSONDecodeError:
        print(json.dumps({"error": "Invalid --args JSON"}))
        sys.exit(1)

    platform = ThreatIntelligencePlatform()
    action = params.get("action", "summary")

    if action == "ping":
        print(json.dumps({"status": "running"}))
    elif action == "summary":
        print(json.dumps(platform.summary()))
    elif action == "collect":
        print(json.dumps(platform.collect_feeds()))
    elif action == "check":
        indicator = params.get("indicator", "")
        print(json.dumps(platform.check_indicator(indicator)))
    else:
        print(json.dumps({"error": f"Unknown action: {action}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
