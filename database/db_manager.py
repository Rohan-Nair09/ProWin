"""
database/db_manager.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import sqlite3
import os
import json
from datetime import datetime

# ── Resolve database path from config ────────────────────────────────────────
_CFG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "settings.json")
with open(_CFG_PATH, "r") as _cfg_fh:
    _CFG = json.load(_cfg_fh)

DB_PATH = os.path.join(os.path.dirname(__file__), "..", _CFG["database_path"])
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# ── DDL ───────────────────────────────────────────────────────────────────────
_DDL = """
CREATE TABLE IF NOT EXISTS processes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pid         INTEGER NOT NULL,
    name        TEXT,
    path        TEXT,
    ppid        INTEGER,
    parent_name TEXT,
    owner       TEXT,
    cpu         REAL    DEFAULT 0.0,
    memory      INTEGER DEFAULT 0,
    severity    TEXT    DEFAULT 'INFO',
    reason      TEXT,
    timestamp   TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    process   TEXT,
    pid       INTEGER,
    parent    TEXT,
    severity  TEXT,
    reason    TEXT,
    timestamp TEXT
);

CREATE TABLE IF NOT EXISTS services (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT,
    display_name TEXT,
    path         TEXT,
    state        TEXT,
    start_type   TEXT,
    is_suspicious INTEGER DEFAULT 0,
    reason       TEXT,
    timestamp    TEXT
);

CREATE TABLE IF NOT EXISTS startup_entries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT,
    path          TEXT,
    source        TEXT,
    is_suspicious INTEGER DEFAULT 0,
    reason        TEXT,
    timestamp     TEXT
);
"""

_VALID_TABLES = {"processes", "alerts", "services", "startup_entries"}


# ── Connection factory ────────────────────────────────────────────────────────

def open_db() -> sqlite3.Connection:
    """
    Return a new SQLite connection configured with Row-dict access.

    Uses WAL (Write-Ahead Logging) journal mode so multiple threads can
    read while a write is in progress, eliminating 'database is locked'
    errors when the scan thread and GUI thread access the DB concurrently.
    timeout=30 gives waiting writers up to 30 s before raising an error.

    Returns
    -------
    sqlite3.Connection
        Ready-to-use connection with row_factory set to sqlite3.Row.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # concurrent read+write support
    conn.execute("PRAGMA synchronous=NORMAL") # safe + faster than FULL
    return conn


# ── Schema bootstrap ──────────────────────────────────────────────────────────

def bootstrap_schema() -> None:
    """
    Execute the DDL script to create all required tables if they do not yet
    exist. Safe to call repeatedly — uses IF NOT EXISTS guards.
    """
    with open_db() as conn:
        conn.executescript(_DDL)
        conn.commit()
    print(f"[DB] ProWin database ready at: {DB_PATH}")


# ── Guard ─────────────────────────────────────────────────────────────────────

def _validate_table(name: str) -> None:
    """Raise ValueError when *name* is not a recognised ProWin table."""
    if name not in _VALID_TABLES:
        raise ValueError(
            f"'{name}' is not a valid ProWin table. "
            f"Expected one of: {sorted(_VALID_TABLES)}"
        )


# ── Process operations ────────────────────────────────────────────────────────

def store_process(proc: dict) -> None:
    """
    Persist a process snapshot dict to the processes table.

    Parameters
    ----------
    proc : dict
        Process record with keys matching the table columns.
    """
    sql = """
        INSERT INTO processes
            (pid, name, path, ppid, parent_name, owner,
             cpu, memory, severity, reason, timestamp)
        VALUES
            (:pid, :name, :path, :ppid, :parent_name, :owner,
             :cpu, :memory, :severity, :reason, :timestamp)
    """
    proc.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    with open_db() as conn:
        conn.execute(sql, proc)
        conn.commit()


def fetch_processes(limit: int = 500) -> list:
    """Return the *limit* most-recently stored process records."""
    with open_db() as conn:
        rows = conn.execute(
            "SELECT * FROM processes ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── Alert operations ──────────────────────────────────────────────────────────

def store_alert(alert: dict) -> None:
    """
    Persist a finding/alert dict to the alerts table.

    Parameters
    ----------
    alert : dict
        Alert record with keys: process, pid, parent, severity, reason,
        timestamp.
    """
    sql = """
        INSERT INTO alerts (process, pid, parent, severity, reason, timestamp)
        VALUES (:process, :pid, :parent, :severity, :reason, :timestamp)
    """
    alert.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    with open_db() as conn:
        conn.execute(sql, alert)
        conn.commit()


def fetch_alerts(limit: int = 500) -> list:
    """Return the *limit* most-recently stored alert records."""
    with open_db() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def tally_alerts_by_level() -> dict:
    """
    Aggregate alert counts grouped by severity level.

    Returns
    -------
    dict
        Mapping of severity string → integer count.
    """
    with open_db() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM alerts GROUP BY severity"
        ).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}


# ── Service operations ────────────────────────────────────────────────────────

def store_service(svc: dict) -> None:
    """Persist a service audit record to the services table."""
    sql = """
        INSERT INTO services
            (service_name, display_name, path, state, start_type,
             is_suspicious, reason, timestamp)
        VALUES
            (:service_name, :display_name, :path, :state, :start_type,
             :is_suspicious, :reason, :timestamp)
    """
    svc.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    with open_db() as conn:
        conn.execute(sql, svc)
        conn.commit()


def fetch_services(limit: int = 500) -> list:
    """Return the *limit* most-recently stored service records."""
    with open_db() as conn:
        rows = conn.execute(
            "SELECT * FROM services ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── Startup-entry operations ──────────────────────────────────────────────────

def store_startup_entry(entry: dict) -> None:
    """Persist a persistence/startup entry to the startup_entries table."""
    sql = """
        INSERT INTO startup_entries
            (name, path, source, is_suspicious, reason, timestamp)
        VALUES
            (:name, :path, :source, :is_suspicious, :reason, :timestamp)
    """
    entry.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    with open_db() as conn:
        conn.execute(sql, entry)
        conn.commit()


def fetch_startup_entries(limit: int = 200) -> list:
    """Return the *limit* most-recently stored startup/persistence entries."""
    with open_db() as conn:
        rows = conn.execute(
            "SELECT * FROM startup_entries ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── Table maintenance ─────────────────────────────────────────────────────────

def wipe_table(table: str) -> None:
    """
    Delete all rows from *table*, used before each fresh scan cycle so stale
    data does not persist between runs.

    Parameters
    ----------
    table : str
        Target table name — must be one of the recognised ProWin tables.

    Raises
    ------
    ValueError
        If *table* is not a recognised table name.
    """
    _validate_table(table)
    with open_db() as conn:
        conn.execute(f"DELETE FROM {table}")  # nosec — validated above
        conn.commit()
