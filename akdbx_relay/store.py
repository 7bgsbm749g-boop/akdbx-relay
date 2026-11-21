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
CREATE TABLE IF NOT EXISTS acme_txt_markers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    record_id TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class TxtMarker:
    """A DNS-01 TXT record the relay is creating or has created."""

    id: int
    name: str
    content: str
    record_id: str | None
    created_at: float = 0.0  # store clock (wall time)


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
        self._migrate()

    def _migrate(self) -> None:
        # Drafts kept only record ids in acme_txt; carry them over as markers.
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='acme_txt'").fetchone():
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute(
                    "INSERT INTO acme_txt_markers (name, content, record_id, created_at) "
                    "SELECT '', '', record_id, created_at FROM acme_txt"
                )
                self.db.execute("DROP TABLE acme_txt")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
            self.db.execute("COMMIT")

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
        """Log an issued certificate. Returns True if it was the broker's first.

        An id with no broker row (the relay's own control certificate) is a
        first certificate when the log has no earlier one for that id.
        """
        now = self.clock()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT has_certificate FROM brokers WHERE id = ?", (broker_id,)
            ).fetchone()
            if row is not None:
                first = not row[0]
            else:
                first = self.db.execute(
                    "SELECT 1 FROM certificates WHERE broker_id = ? LIMIT 1", (broker_id,)
                ).fetchone() is None
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

    # Cleanup markers for ACME TXT records. A marker is written before the
    # record is created and removed after the record is deleted.

    def add_txt_marker(self, name: str, content: str) -> TxtMarker:
        now = self.clock()
        cur = self.db.execute(
            "INSERT INTO acme_txt_markers (name, content, record_id, created_at) VALUES (?, ?, NULL, ?)",
            (name, content, now),
        )
        return TxtMarker(int(cur.lastrowid), name, content, None, now)

    def set_txt_marker_record(self, marker_id: int, record_id: str) -> None:
        self.db.execute("UPDATE acme_txt_markers SET record_id = ? WHERE id = ?", (record_id, marker_id))

    def remove_txt_marker(self, marker_id: int) -> None:
        self.db.execute("DELETE FROM acme_txt_markers WHERE id = ?", (marker_id,))

    def txt_markers(self) -> list[TxtMarker]:
        rows = self.db.execute(
            "SELECT id, name, content, record_id, created_at FROM acme_txt_markers ORDER BY id"
        ).fetchall()
        return [TxtMarker(r[0], r[1], r[2], r[3], r[4]) for r in rows]

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
