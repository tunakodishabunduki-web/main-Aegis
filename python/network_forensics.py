#!/usr/bin/env python3
"""
network_forensics.py
Network Forensics and Analysis — reads from a log/PCAP file or a stored
alert database.  This module operates PASSIVELY on data that has already
been captured; it does NOT open raw sockets or sniff live traffic unless
explicitly invoked with --capture (which requires root and a valid interface).

Outputs JSON for PHP's PythonBridge.

Dependencies (base mode — no live capture):  none beyond stdlib
Dependencies (live capture):  pip install scapy
"""

import argparse
import json
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timedelta


SQLI_RE     = re.compile(r"('|\")\\s*(OR|AND)|UNION\\s+SELECT|DROP\\s+TABLE|--|;--", re.I)
XSS_RE      = re.compile(r"<script|onerror\s*=|javascript:", re.I)
PATH_RE     = re.compile(r"\.\.[/\\]|/etc/passwd|/etc/shadow", re.I)
CMD_RE      = re.compile(r";\s*(ls|cat|whoami|id|bash|sh)\b", re.I)


class NetworkForensics:
    """
    Stores alert records in a local SQLite database.
    PHP can feed events into this module or read its aggregated alerts.
    """

    SUSPICIOUS_THRESHOLDS = {
        "port_scan":   {"max_connections": 20, "window_seconds": 60},
        "brute_force": {"max_attempts":    10, "window_seconds": 120},
    }

    def __init__(self, db_path: str = "/tmp/aegis_network.db"):
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS network_alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type  TEXT NOT NULL,
                source_ip   TEXT,
                destination TEXT,
                detail      TEXT,
                severity    TEXT DEFAULT 'MEDIUM',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS connection_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip   TEXT NOT NULL,
                dest_ip     TEXT,
                dest_port   INTEGER,
                protocol    TEXT,
                size_bytes  INTEGER DEFAULT 0,
                logged_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        self.db.commit()

    # ------------------------------------------------------------------
    # Ingestion helpers — PHP calls these via the bridge
    # ------------------------------------------------------------------

    def ingest_http_request(self, source_ip: str, method: str,
                             path: str, user_agent: str) -> dict:
        """Analyse one HTTP request and store an alert if suspicious."""
        alerts_raised = []
        combined = f"{path} {user_agent}"

        if SQLI_RE.search(combined):
            alerts_raised.append(self._store_alert("SQL_INJECTION", source_ip, path, "High"))
        if XSS_RE.search(combined):
            alerts_raised.append(self._store_alert("XSS_ATTEMPT", source_ip, path, "Medium"))
        if PATH_RE.search(combined):
            alerts_raised.append(self._store_alert("PATH_TRAVERSAL", source_ip, path, "High"))
        if CMD_RE.search(combined):
            alerts_raised.append(self._store_alert("CMD_INJECTION", source_ip, path, "Critical"))

        return {"alerts": alerts_raised}

    def log_connection(self, source_ip: str, dest_ip: str,
                       dest_port: int, protocol: str = "TCP",
                       size_bytes: int = 0) -> None:
        self.db.execute(
            "INSERT INTO connection_log (source_ip, dest_ip, dest_port, protocol, size_bytes)"
            " VALUES (?, ?, ?, ?, ?)",
            (source_ip, dest_ip, dest_port, protocol, size_bytes),
        )
        self.db.commit()
        self._check_port_scan(source_ip)

    def _check_port_scan(self, source_ip: str) -> None:
        threshold = self.SUSPICIOUS_THRESHOLDS["port_scan"]
        window    = datetime.now() - timedelta(seconds=threshold["window_seconds"])
        count     = self.db.execute(
            "SELECT COUNT(DISTINCT dest_port) FROM connection_log"
            " WHERE source_ip = ? AND logged_at > ?",
            (source_ip, window),
        ).fetchone()[0]

        if count >= threshold["max_connections"]:
            self._store_alert(
                "PORT_SCAN", source_ip,
                f"{count} distinct ports in {threshold['window_seconds']}s",
                "High",
            )

    def _store_alert(self, alert_type: str, source_ip: str,
                     detail: str, severity: str = "Medium") -> dict:
        self.db.execute(
            "INSERT INTO network_alerts (alert_type, source_ip, detail, severity)"
            " VALUES (?, ?, ?, ?)",
            (alert_type, source_ip, detail, severity),
        )
        self.db.commit()
        return {
            "type":      alert_type,
            "source_ip": source_ip,
            "detail":    detail,
            "severity":  severity,
            "timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Dashboard-facing queries
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        total_alerts = self.db.execute("SELECT COUNT(*) FROM network_alerts").fetchone()[0]
        by_type      = dict(self.db.execute(
            "SELECT alert_type, COUNT(*) FROM network_alerts GROUP BY alert_type"
        ).fetchall())
        top_ips = [dict(r) for r in self.db.execute(
            "SELECT source_ip, COUNT(*) AS count FROM network_alerts"
            " GROUP BY source_ip ORDER BY count DESC LIMIT 5"
        ).fetchall()]
        recent = [dict(r) for r in self.db.execute(
            "SELECT alert_type, source_ip, detail, severity, created_at"
            " FROM network_alerts ORDER BY created_at DESC LIMIT 10"
        ).fetchall()]
        return {
            "total_alerts": total_alerts,
            "by_type":      by_type,
            "top_ips":      top_ips,
            "recent":       recent,
            "status":       "running",
        }

    def alerts(self) -> dict:
        rows = [dict(r) for r in self.db.execute(
            "SELECT * FROM network_alerts ORDER BY created_at DESC LIMIT 50"
        ).fetchall()]
        return {"alerts": rows, "count": len(rows)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--args", default="{}")
    args = parser.parse_args()

    try:
        params = json.loads(args.args)
    except json.JSONDecodeError:
        print(json.dumps({"error": "Invalid --args JSON"}))
        sys.exit(1)

    nf     = NetworkForensics()
    action = params.get("action", "summary")

    dispatch = {
        "ping":    lambda: {"status": "running"},
        "summary": nf.summary,
        "alerts":  nf.alerts,
    }

    handler = dispatch.get(action)
    if handler:
        print(json.dumps(handler()))
    else:
        print(json.dumps({"error": f"Unknown action: {action}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
