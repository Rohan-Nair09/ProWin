"""
gui/alerts.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import threading
from datetime import datetime
from collections import deque
from utils.logger import emit_alert
from database import db_manager

# Maximum number of findings to retain in memory across all scan cycles
_QUEUE_LIMIT = 1000

_lock      = threading.Lock()
_findings  = deque(maxlen=_QUEUE_LIMIT)
_ui_hooks  = []   # callbacks registered by the GUI to trigger reactive refresh


# ── Level metadata ────────────────────────────────────────────────────────────

LEVEL_RANK: dict = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
}

LEVEL_COLORS: dict = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#17a2b8",
    "INFO":     "#6c757d",
}

LEVEL_ICONS: dict = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


# ── GUI hook registration ─────────────────────────────────────────────────────

def bind_ui_hook(callback) -> None:
    """
    Register a callable that will be invoked whenever a new finding is
    dispatched. Used by the dashboard to trigger reactive table refreshes.

    Parameters
    ----------
    callback : callable
        Function accepting a single finding dict argument.
    """
    _ui_hooks.append(callback)


# ── Dispatch ──────────────────────────────────────────────────────────────────

def dispatch_finding(finding: dict) -> None:
    """
    Route a single security finding to all four output sinks:
      1. In-memory bounded deque (for GUI display).
      2. Multi-sink logger (TXT / CSV / JSONL).
      3. SQLite database (for persistence across sessions).
      4. All registered GUI refresh hooks.

    Parameters
    ----------
    finding : dict
        Finding record with expected keys: process, pid, parent, severity,
        reason. Missing keys are defaulted safely.
    """
    finding.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    finding.setdefault("severity",  "INFO")
    finding.setdefault("process",   "")
    finding.setdefault("pid",       0)
    finding.setdefault("parent",    "")
    finding.setdefault("reason",    "")

    with _lock:
        _findings.append(finding)

    emit_alert(finding)

    try:
        db_manager.store_alert(finding)
    except Exception:
        pass

    for hook in _ui_hooks:
        try:
            hook(finding)
        except Exception:
            pass


def dispatch_findings(findings: list) -> None:
    """
    Bulk-dispatch a list of finding dicts by calling dispatch_finding for each.

    Parameters
    ----------
    findings : list[dict]
        Zero or more finding records to dispatch in order.
    """
    for item in findings:
        dispatch_finding(item)


# ── Query ─────────────────────────────────────────────────────────────────────

def fetch_all_findings() -> list:
    """
    Return a snapshot of all currently queued findings as a plain list.
    The returned list is a copy and is safe to iterate without holding the lock.
    """
    with _lock:
        return list(_findings)


def fetch_findings_by_level(severity: str) -> list:
    """
    Return findings filtered to a specific severity level.

    Parameters
    ----------
    severity : str
        Target severity (case-insensitive).

    Returns
    -------
    list[dict]
        Subset of queued findings matching the requested severity.
    """
    with _lock:
        return [
            f for f in _findings
            if f.get("severity", "").upper() == severity.upper()
        ]


def tally_by_level() -> dict:
    """
    Count queued findings grouped by severity level.

    Returns
    -------
    dict
        {severity_string: count_int} for all five severity levels.
    """
    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    with _lock:
        for f in _findings:
            lvl = f.get("severity", "INFO").upper()
            if lvl in totals:
                totals[lvl] += 1
    return totals


def flush_findings() -> None:
    """Clear the entire in-memory finding queue."""
    with _lock:
        _findings.clear()


# ── Formatting ────────────────────────────────────────────────────────────────

def render_console_line(finding: dict) -> str:
    """
    Format a finding dict as a single-line console string suitable for
    printing to stdout or a terminal log view.

    Parameters
    ----------
    finding : dict
        Finding record to render.

    Returns
    -------
    str
        Formatted line with icon, severity, timestamp, process info, and reason.
    """
    icon = LEVEL_ICONS.get(finding.get("severity", "INFO"), "•")
    return (
        f"{icon} [{finding.get('severity', '?'):8s}] "
        f"{finding.get('timestamp', '')[:16]} | "
        f"{finding.get('process', '')} (PID:{finding.get('pid', '')}) | "
        f"Parent: {finding.get('parent', '')} | "
        f"{finding.get('reason', '')}"
    )
