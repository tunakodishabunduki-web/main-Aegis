#!/usr/bin/env python3
"""
deception_grid.py
Active Deception System — manages honeytokens and decoy services.
Outputs JSON for PHP's PythonBridge.

Note: Token values (fake credentials, fake file names) are generated solely
as bait for attackers who access systems they are not authorised to access.
They are never real credentials and are clearly labelled as decoys in the DB.
"""

import argparse
import hashlib
import json
import random
import secrets
import sqlite3
import string
import sys
from datetime import datetime


class DeceptionGrid:
    TOKEN_TYPES = {
        "API_KEY":  lambda: secrets.token_hex(16),
        "PASSWORD": lambda: secrets.token_urlsafe(12),
        "EMAIL":    lambda: f"{''.join(random.choices(string.ascii_lowercase, k=8))}@decoy.internal",
        "FILE":     lambda: f"confidential_{random.randint(100, 999)}.{'pdf' if random.random() > .5 else 'xlsx'}",
    }

    def __init__(self, db_path: str = "/tmp/aegis_deception.db"):
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS honeytokens (
                id             TEXT PRIMARY KEY,
                token_type     TEXT,
                value          TEXT,
                created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                activated      INTEGER DEFAULT 0,
                activated_at   TIMESTAMP,
                attacker_ip    TEXT
            );
            CREATE TABLE IF NOT EXISTS decoy_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id    TEXT,
                attacker_ip TEXT,
                event_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        self.db.commit()

    def create_honeytoken(self, token_type: str) -> dict:
        token_type = token_type.upper()
        if token_type not in self.TOKEN_TYPES:
            return {"error": f"Unknown token type. Valid: {list(self.TOKEN_TYPES.keys())}"}

        token_id = secrets.token_hex(8)
        value    = self.TOKEN_TYPES[token_type]()

        self.db.execute(
            "INSERT INTO honeytokens (id, token_type, value) VALUES (?, ?, ?)",
            (token_id, token_type, value),
        )
        self.db.commit()
        return {"id": token_id, "type": token_type, "value": value, "created": datetime.now().isoformat()}

    def record_trigger(self, token_id: str, attacker_ip: str) -> dict:
        self.db.execute(
            "UPDATE honeytokens SET activated = 1, activated_at = ?, attacker_ip = ? WHERE id = ?",
            (datetime.now(), attacker_ip, token_id),
        )
        self.db.execute(
            "INSERT INTO decoy_events (token_id, attacker_ip) VALUES (?, ?)",
            (token_id, attacker_ip),
        )
        self.db.commit()
        return {"status": "recorded", "token_id": token_id, "attacker": attacker_ip}

    def status(self) -> dict:
        total     = self.db.execute("SELECT COUNT(*) FROM honeytokens").fetchone()[0]
        triggered = self.db.execute("SELECT COUNT(*) FROM honeytokens WHERE activated = 1").fetchone()[0]
        recent    = [
            dict(r) for r in self.db.execute(
                "SELECT id, token_type, attacker_ip, activated_at FROM honeytokens"
                " WHERE activated = 1 ORDER BY activated_at DESC LIMIT 10"
            ).fetchall()
        ]
        return {
            "total_tokens": total,
            "triggered":    triggered,
            "recent_triggers": recent,
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

    grid   = DeceptionGrid()
    action = params.get("action", "status")

    if action == "ping":
        print(json.dumps({"status": "running"}))
    elif action == "status":
        print(json.dumps(grid.status()))
    elif action == "create_token":
        t = params.get("type", "API_KEY")
        print(json.dumps(grid.create_honeytoken(t)))
    elif action == "trigger":
        print(json.dumps(grid.record_trigger(params.get("token_id", ""), params.get("attacker_ip", ""))))
    else:
        print(json.dumps({"error": f"Unknown action: {action}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
