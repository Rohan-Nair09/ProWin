"""
utils/logger.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import os
import csv
import json
import logging
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler

from utils.helpers import load_config

# ── Boot configuration ────────────────────────────────────────────────────────
_CFG      = load_config()
_LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", _CFG.get("logs_path", "logs/"))
_MAX_BYTES = _CFG.get("max_log_size_mb", 10) * 1024 * 1024

os.makedirs(_LOGS_DIR, exist_ok=True)

_write_lock = threading.Lock()

# ── CSV schema ────────────────────────────────────────────────────────────────
_CSV_PATH    = os.path.join(_LOGS_DIR, "audit.csv")
_CSV_COLUMNS = ["timestamp", "event_type", "process", "pid",
                "parent", "path", "severity", "reason"]

# ── JSON audit path ───────────────────────────────────────────────────────────
_JSONL_PATH = os.path.join(_LOGS_DIR, "audit.jsonl")


class MultiSinkLogger:
    """
    Writes log records to a rotating text file, a CSV audit file, and a
    newline-delimited JSON file in a single call, thread-safely.

    Attributes
    ----------
    _txt : logging.Logger
        Standard Python logger that writes to sentinel.log with rotation.
    """

    def __init__(self) -> None:
        self._txt = self._init_text_logger()
        self._bootstrap_csv()

    # ── Text logger ───────────────────────────────────────────────────────────

    def _init_text_logger(self) -> logging.Logger:
        log_path = os.path.join(_LOGS_DIR, "sentinel.log")
        logger   = logging.getLogger("SentinelEye")
        logger.setLevel(logging.DEBUG)

        if not logger.handlers:
            file_handler = RotatingFileHandler(
                log_path, maxBytes=_MAX_BYTES, backupCount=5, encoding="utf-8"
            )
            file_handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)-8s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            ))
            logger.addHandler(file_handler)

            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(
                logging.Formatter("[%(levelname)s] %(message)s")
            )
            logger.addHandler(console_handler)

        return logger

    # ── CSV bootstrap ─────────────────────────────────────────────────────────

    def _bootstrap_csv(self) -> None:
        """Write the header row if the CSV file is new or empty."""
        if not os.path.exists(_CSV_PATH) or os.path.getsize(_CSV_PATH) == 0:
            with open(_CSV_PATH, "w", newline="", encoding="utf-8") as fh:
                csv.DictWriter(fh, fieldnames=_CSV_COLUMNS).writeheader()

    # ── Core emit ─────────────────────────────────────────────────────────────

    def emit(
        self,
        event_type: str,
        process:    str = "",
        pid:        int = 0,
        parent:     str = "",
        path:       str = "",
        severity:   str = "INFO",
        reason:     str = "",
    ) -> None:
        """
        Record a monitoring event across all three output sinks atomically.

        Parameters
        ----------
        event_type : str
            Category tag — one of PROCESS, SERVICE, STARTUP, ALERT, SYSTEM.
        process    : str
            Executable name of the subject process.
        pid        : int
            Process identifier.
        parent     : str
            Name of the parent process.
        path       : str
            Filesystem path of the executable, if known.
        severity   : str
            One of DEBUG, INFO, LOW, MEDIUM, HIGH, CRITICAL.
        reason     : str
            Human-readable description of why the event was raised.
        """
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = (
            f"[{event_type}] {process} (PID:{pid})"
            f" | Parent:{parent} | {severity} | {reason}"
        )

        # Map to a Python logging level
        py_level = getattr(
            logging,
            severity if severity in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "INFO"
        )
        self._txt.log(py_level, msg)

        record = {
            "timestamp":  ts,
            "event_type": event_type,
            "process":    process,
            "pid":        pid,
            "parent":     parent,
            "path":       path,
            "severity":   severity,
            "reason":     reason,
        }

        with _write_lock:
            # Append to CSV
            with open(_CSV_PATH, "a", newline="", encoding="utf-8") as fh:
                csv.DictWriter(fh, fieldnames=_CSV_COLUMNS).writerow(record)
            # Append to JSONL
            with open(_JSONL_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")

    # ── Convenience wrappers ──────────────────────────────────────────────────

    def record_info(self, message: str) -> None:
        """Write an informational message to the text log only."""
        self._txt.info(message)

    def record_warning(self, message: str) -> None:
        """Write a warning message to the text log only."""
        self._txt.warning(message)

    def record_error(self, message: str) -> None:
        """Write an error message to the text log only."""
        self._txt.error(message)


# ── Module-level singleton ────────────────────────────────────────────────────
_logger = MultiSinkLogger()


# ── Public API ────────────────────────────────────────────────────────────────

def emit_event(
    event_type: str,
    process:    str = "",
    pid:        int = 0,
    parent:     str = "",
    path:       str = "",
    severity:   str = "INFO",
    reason:     str = "",
) -> None:
    """Thin wrapper delegating to the module-level MultiSinkLogger instance."""
    _logger.emit(event_type, process, pid, parent, path, severity, reason)


def emit_alert(alert: dict) -> None:
    """
    Convenience function that unpacks an alert dict and routes it through
    emit_event with event_type='ALERT'.

    Parameters
    ----------
    alert : dict
        Dictionary with keys: process, pid, parent, path, severity, reason.
    """
    _logger.emit(
        event_type="ALERT",
        process=alert.get("process", ""),
        pid=alert.get("pid", 0),
        parent=alert.get("parent", ""),
        path=alert.get("path", ""),
        severity=alert.get("severity", "INFO"),
        reason=alert.get("reason", ""),
    )


def record_info(message: str) -> None:
    """Write a plain INFO-level message to the text log."""
    _logger.record_info(message)


def record_warning(message: str) -> None:
    """Write a WARNING-level message to the text log."""
    _logger.record_warning(message)


def record_error(message: str) -> None:
    """Write an ERROR-level message to the text log."""
    _logger.record_error(message)
