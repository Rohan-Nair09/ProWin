"""
utils/helpers.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import os
import sys
import ctypes
import hashlib
import json
from datetime import datetime


# ── Privilege Check ───────────────────────────────────────────────────────────

def is_admin() -> bool:
    """
    Determine whether the current Python process holds Windows Administrator
    privileges by querying the shell32 API.

    Returns
    -------
    bool
        True if the process is elevated, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def admin_privilege_warning() -> str | None:
    """
    Produce a human-readable warning when ProWin is not elevated.

    Returns
    -------
    str | None
        A multi-line warning string if privileges are missing, else None.
    """
    if not is_admin():
        return (
            "⚠  ProWin is running WITHOUT Administrator rights.\n"
            "WMI service queries, process owner resolution, and digital-signature\n"
            "verification will be limited. Re-launch via 'Run as administrator'\n"
            "for full monitoring coverage."
        )
    return None


# ── Size Formatting ───────────────────────────────────────────────────────────

def humanize_size(byte_count: int) -> str:
    """
    Convert a raw byte count into a human-readable string with appropriate
    unit suffix (B, KB, MB, GB, TB, PB).

    Parameters
    ----------
    byte_count : int
        Number of bytes to format.

    Returns
    -------
    str
        Formatted string such as '4.2 MB' or '512.0 KB'.
    """
    try:
        value = int(byte_count)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(value) < 1024.0:
                return f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} PB"
    except Exception:
        return "N/A"


def format_timestamp(ts: str | None = None) -> str:
    """Return *ts* unchanged if provided, otherwise the current timestamp."""
    if ts:
        return ts
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Severity / Level Colour Palette ──────────────────────────────────────────

# Unified palette: each severity level maps to a foreground and background hex.
LEVEL_PALETTE: dict = {
    "INFO":     {"fg": "#6c757d", "bg": "#2a2a3a"},
    "LOW":      {"fg": "#17a2b8", "bg": "#1a2a3a"},
    "MEDIUM":   {"fg": "#ffc107", "bg": "#2a2a1a"},
    "HIGH":     {"fg": "#fd7e14", "bg": "#2a1a0a"},
    "CRITICAL": {"fg": "#dc3545", "bg": "#3a0a0a"},
}


def level_to_hex(level: str) -> str:
    """
    Retrieve the foreground hex colour for a given severity level.

    Parameters
    ----------
    level : str
        One of INFO, LOW, MEDIUM, HIGH, CRITICAL (case-insensitive).

    Returns
    -------
    str
        Hex colour string such as '#ffc107'.
    """
    return LEVEL_PALETTE.get(level.upper(), {}).get("fg", "#ffffff")


def level_to_bg_hex(level: str) -> str:
    """
    Retrieve the background hex colour for a given severity level, intended
    for row-highlight use in the GUI tables.

    Parameters
    ----------
    level : str
        Severity level string.

    Returns
    -------
    str
        Hex colour string for the row background.
    """
    return LEVEL_PALETTE.get(level.upper(), {}).get("bg", "#1e1e2e")


# ── File Integrity ────────────────────────────────────────────────────────────

def compute_file_hash(filepath: str) -> str | None:
    """
    Calculate the SHA-256 digest of a file in streaming chunks so that large
    executables do not exhaust available memory.

    Parameters
    ----------
    filepath : str
        Absolute path to the target file.

    Returns
    -------
    str | None
        64-character lowercase hex digest, or None if the file cannot be read.
    """
    try:
        digest = hashlib.sha256()
        with open(filepath, "rb") as fh:
            for block in iter(lambda: fh.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()
    except Exception:
        return None


# ── Config Loader ─────────────────────────────────────────────────────────────

def load_config() -> dict:
    """
    Load and return the ProWin configuration from settings.json located
    in the project's config/ directory.

    Returns
    -------
    dict
        Parsed JSON configuration dictionary.
    """
    cfg_path = os.path.join(os.path.dirname(__file__), "..", "config", "settings.json")
    with open(cfg_path, "r") as fh:
        return json.load(fh)


# ── Process Owner Resolution ──────────────────────────────────────────────────

def resolve_proc_owner(proc_obj) -> str:
    """
    Attempt to retrieve the Windows account name that owns a given
    psutil.Process instance, returning 'N/A' gracefully on any failure.

    Parameters
    ----------
    proc_obj : psutil.Process
        Live process handle from psutil.

    Returns
    -------
    str
        Account name (e.g. 'DESKTOP-ABC\\Rohan') or 'N/A'.
    """
    try:
        return proc_obj.username()
    except Exception:
        return "N/A"
