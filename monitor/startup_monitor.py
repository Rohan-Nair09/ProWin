"""
monitor/startup_monitor.py
SentinelEye — Startup and persistence location scanner.

Reads Windows registry Run/RunOnce keys and shell:startup folder contents to
enumerate all autostart entries. Each entry is evaluated for indicators of
malicious persistence.

Author  : Rohan Nair
Project : SentinelEye — Endpoint Monitoring Agent
"""

import os
import winreg
import glob
from datetime import datetime
from utils.helpers import load_config

_CFG       = load_config()
_RISKY_DIRS = _CFG.get("suspicious_paths", [])

# ── Registry autostart keys ───────────────────────────────────────────────────
# Each tuple holds (hive_constant, subkey_path, human_readable_label).
REGISTRY_RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run",
     "HKCU\\Run"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run",
     "HKLM\\Run"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKLM\\RunOnce"),
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKCU\\RunOnce"),
    # WOW64 mirror for 32-bit entries on 64-bit Windows
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
     "HKLM\\Run (WOW64)"),
]

# ── Startup folder locations ──────────────────────────────────────────────────
SHELL_STARTUP_DIRS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
]

# Script extensions that are inherently risky in an autostart context
_RISKY_EXTENSIONS = {".bat", ".vbs", ".js", ".ps1", ".cmd", ".hta", ".wsf"}


# ── Risk evaluation ───────────────────────────────────────────────────────────

def _path_is_risky(path: str) -> tuple:
    """
    Determine whether a filesystem path is associated with known-risky
    locations or uses a script extension that should not appear at startup.

    Parameters
    ----------
    path : str
        Full file path from the registry value or startup folder listing.

    Returns
    -------
    tuple[bool, str]
        (True, reason_string) if the path is suspicious, else (False, '').
    """
    for risky_segment in _RISKY_DIRS:
        if risky_segment.lower() in path.lower():
            return True, f"Startup entry originates from a high-risk directory: {path}"

    _, ext = os.path.splitext(path)
    if ext.lower() in _RISKY_EXTENSIONS:
        return True, f"Startup entry uses a risky script type ('{ext}'): {path}"

    return False, ""


# ── Registry reader ───────────────────────────────────────────────────────────

def _parse_reg_run_key(hive, subkey: str, label: str) -> list:
    """
    Enumerate all values under a single registry Run/RunOnce key and build
    an entry dict for each autostart item found.

    Parameters
    ----------
    hive   : winreg constant — HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE.
    subkey : str             — Registry subkey path.
    label  : str             — Human-readable key label for the 'source' field.

    Returns
    -------
    list[dict]
        Startup entry records for each value found under the key.
    """
    entries = []
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        idx = 0
        while True:
            try:
                value_name, value_data, _ = winreg.EnumValue(key, idx)
                flagged, reason = _path_is_risky(value_data)
                entries.append({
                    "name":          value_name,
                    "path":          value_data,
                    "source":        label,
                    "is_suspicious": 1 if flagged else 0,
                    "reason":        reason,
                    "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })
                idx += 1
            except OSError:
                break   # no more values in this key
        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError):
        pass    # key inaccessible — skip silently
    return entries


# ── Startup folder scanner ────────────────────────────────────────────────────

def _scan_shell_startup() -> list:
    """
    Walk both user-level and all-users shell:startup folders and return a
    record for every file found therein.

    Returns
    -------
    list[dict]
        One entry dict per file discovered in the startup folders.
    """
    entries = []
    for folder in SHELL_STARTUP_DIRS:
        if not os.path.isdir(folder):
            continue
        for filepath in glob.glob(os.path.join(folder, "*")):
            flagged, reason = _path_is_risky(filepath)
            entries.append({
                "name":          os.path.basename(filepath),
                "path":          filepath,
                "source":        "Startup Folder",
                "is_suspicious": 1 if flagged else 0,
                "reason":        reason,
                "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
    return entries


# ── Public interface ──────────────────────────────────────────────────────────

def scan_startup_locations() -> list:
    """
    Aggregate all autostart entries from every monitored registry Run key and
    both startup folder locations.

    Returns
    -------
    list[dict]
        Combined list of startup/persistence entry records, each containing:
        name, path, source, is_suspicious, reason, timestamp.
    """
    entries = []
    for (hive, subkey, label) in REGISTRY_RUN_KEYS:
        entries.extend(_parse_reg_run_key(hive, subkey, label))
    entries.extend(_scan_shell_startup())
    return entries
