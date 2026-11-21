"""SQLite state: brokers, secret hashes, and the issued-certificate log.

Nothing here identifies a person: no client IPs, no CSRs, no certificates'
private data. The certificate log keeps only times, so the relay can count
its Let's Encrypt budget.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Callable

WEEK = 7 * 24 * 3600.0
DAY = 24 * 3600.0
# A registration without a certificate holds a budget slot for this long, so a
# burst of registrations cannot overshoot the weekly certificate budget.
PENDING_RESERVATION = DAY

_SCHEMA = """
CREATE TABLE IF NOT EXISTS brokers (
    id TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL,
    client TEXT NOT NULL DEFAULT '',
    has_certificate INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    broker_id TEXT NOT NULL,
    issued_at REAL NOT NULL,
    not_after REAL NOT NULL,
    first_time INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS certificates_issued ON certificates (issued_at);
CREATE INDEX IF NOT EXISTS certificates_broker ON certificates (broker_id, issued_at);
CREATE TABLE IF NOT EXISTS acme_txt (
    record_id TEXT PRIMARY KEY,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class Broker:
    id: str
    created_at: float
    has_certificate: bool


class Store:
    def __init__(self, path: str, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        if path != ":memory:":
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, mode=0o700, exist_ok=True)
            if not os.path.exists(path):
                os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(_SCHEMA)

    def close(self) -> None:
        self.db.close()

    # Brokers

    def add_broker(self, broker_id: str, secret_hash: str, client: str) -> bool:
        try:
            self.db.execute(
                "INSERT INTO brokers (id, secret_hash, created_at, client) VALUES (?, ?, ?, ?)",
                (broker_id, secret_hash, self.clock(), client),
            )
        except sqlite3.IntegrityError:
            return False
        return True

    def broker_by_secret_hash(self, secret_hash: str) -> Broker | None:
        row = self.db.execute(
            "SELECT id, created_at, has_certificate FROM brokers WHERE secret_hash = ?",
            (secret_hash,),
        ).fetchone()
        return Broker(row[0], row[1], bool(row[2])) if row else None

    def broker_exists(self, broker_id: str) -> bool:
        return self.db.execute("SELECT 1 FROM brokers WHERE id = ?", (broker_id,)).fetchone() is not None

    def broker_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM brokers").fetchone()[0]

    # Certificate log and budget

    def record_certificate(self, broker_id: str, not_after: float) -> bool:
        """Log an issued certificate. Returns True if it was the broker's first."""
        now = self.clock()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT has_certificate FROM brokers WHERE id = ?", (broker_id,)
            ).fetchone()
            first = not (row and row[0])
            self.db.execute(
                "INSERT INTO certificates (broker_id, issued_at, not_after, first_time) VALUES (?, ?, ?, ?)",
                (broker_id, now, not_after, 1 if first else 0),
            )
            self.db.execute("UPDATE brokers SET has_certificate = 1 WHERE id = ?", (broker_id,))
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")
        return first

    def first_time_certificates(self) -> list[float]:
        """Issue times of first-time certificates in the rolling 7-day window."""
        since = self.clock() - WEEK
        rows = self.db.execute(
            "SELECT issued_at FROM certificates WHERE first_time = 1 AND issued_at > ? ORDER BY issued_at",
            (since,),
        ).fetchall()
        return [r[0] for r in rows]

    def pending_registrations(self) -> list[float]:
        """Creation times of recent brokers that have no certificate yet."""
        since = self.clock() - PENDING_RESERVATION
        rows = self.db.execute(
            "SELECT created_at FROM brokers WHERE has_certificate = 0 AND created_at > ? ORDER BY created_at",
            (since,),
        ).fetchall()
        return [r[0] for r in rows]

    def broker_certificates_this_week(self, broker_id: str) -> list[float]:
        since = self.clock() - WEEK
        rows = self.db.execute(
            "SELECT issued_at FROM certificates WHERE broker_id = ? AND issued_at > ? ORDER BY issued_at",
            (broker_id, since),
        ).fetchall()
        return [r[0] for r in rows]

    # ACME TXT records that may need cleanup after a crash

    def add_txt_record(self, record_id: str) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO acme_txt (record_id, created_at) VALUES (?, ?)",
            (record_id, self.clock()),
        )

    def remove_txt_record(self, record_id: str) -> None:
        self.db.execute("DELETE FROM acme_txt WHERE record_id = ?", (record_id,))

    def txt_records(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT record_id FROM acme_txt").fetchall()]

    # Meta

    def get_meta(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


class Budget:
    """The relay's share of the Let's Encrypt new-certificate limit."""

    def __init__(self, store: Store, budget: int, hard_limit: int, per_broker_week: int) -> None:
        self.store = store
        self.budget = budget
        self.hard_limit = hard_limit
        self.per_broker_week = per_broker_week

    def _retry(self, times: list[float], lifetime: float) -> int:
        now = self.store.clock()
        if not times:
            return 60
        return max(60, int(min(t + lifetime for t in times) - now) + 1)

    def registration_retry_after(self) -> int | None:
        """None if a new registration may proceed, else seconds to wait."""
        issued = self.store.first_time_certificates()
        pending = self.store.pending_registrations()
        if len(issued) + len(pending) < self.budget:
            return None
        now = self.store.clock()
        expiries = [t + WEEK for t in issued] + [t + PENDING_RESERVATION for t in pending]
        return max(60, int(min(expiries) - now) + 1)

    def first_issuance_retry_after(self, in_flight: int = 0) -> int | None:
        """None if a first-time certificate may be ordered now (counting orders in progress)."""
        issued = self.store.first_time_certificates()
        if len(issued) + in_flight < self.hard_limit:
            return None
        return self._retry(issued, WEEK)

    def broker_retry_after(self, broker_id: str) -> int | None:
        times = self.store.broker_certificates_this_week(broker_id)
        if len(times) < self.per_broker_week:
            return None
        oldest_needed = times[len(times) - self.per_broker_week]
        return self._retry([oldest_needed], WEEK)

    def status(self) -> dict[str, int]:
        return {
            "first_time_certificates_7d": len(self.store.first_time_certificates()),
            "pending_registrations": len(self.store.pending_registrations()),
            "budget": self.budget,
        }
