"""
detection/rules_engine.py
SentinelEye — Rule-based threat assessment engine.

Evaluates individual processes, parent→child spawn relationships, and Windows
services against a curated set of behavioural rules. Returns structured
finding dictionaries consumed by the alert dispatch layer.

Author  : Rohan Nair
Project : SentinelEye — Endpoint Monitoring Agent
"""

import os
import json
from datetime import datetime
from detection.whitelist import is_trusted, skip_cpu_check
from detection.blacklist import is_known_threat

# ── Configuration ─────────────────────────────────────────────────────────────
_CFG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "settings.json")
with open(_CFG_PATH) as fh:
    _CFG = json.load(fh)

_RISKY_PATHS: list  = _CFG.get("suspicious_paths", [])
_CPU_CEILING: float = _CFG.get("cpu_alert_threshold", 80.0)


# ── Spawn-chain rule table ────────────────────────────────────────────────────
#
# Maps a parent executable (lowercase) to a list of (child_exe, description,
# severity) tuples that represent known-malicious parent→child combinations.
# The descriptions are written to be unambiguous in an audit report context.

PROC_SPAWN_RULES: dict = {
    "winword.exe": [
        ("powershell.exe", "Word launched PowerShell — hallmark of a malicious Office macro", "CRITICAL"),
        ("cmd.exe",        "Word opened a Command Prompt — likely macro-based shell execution",  "HIGH"),
        ("wscript.exe",    "Word invoked WScript — suspicious scripted payload delivery",        "HIGH"),
        ("cscript.exe",    "Word invoked CScript — script execution via Office document",        "HIGH"),
        ("mshta.exe",      "Word spawned MSHTA — HTML Application used as exploit dropper",     "CRITICAL"),
        ("regsvr32.exe",   "Word called RegSvr32 — COM scriptlet registration technique",       "CRITICAL"),
        ("rundll32.exe",   "Word used RunDLL32 — possible DLL side-load from document",         "HIGH"),
    ],
    "excel.exe": [
        ("powershell.exe", "Excel triggered PowerShell — macro or DDE formula abuse",           "CRITICAL"),
        ("cmd.exe",        "Excel opened CMD — script abuse through spreadsheet cell formula",   "HIGH"),
        ("wscript.exe",    "Excel launched WScript — malicious spreadsheet scripting",           "HIGH"),
        ("mshta.exe",      "Excel invoked MSHTA — HTML Application payload from spreadsheet",   "CRITICAL"),
    ],
    "outlook.exe": [
        ("powershell.exe", "Outlook launched PowerShell — likely malicious email attachment",   "CRITICAL"),
        ("wscript.exe",    "Outlook ran WScript — malicious attachment script execution",        "HIGH"),
        ("cmd.exe",        "Outlook opened CMD — suspicious attachment or rule trigger",         "HIGH"),
        ("mshta.exe",      "Outlook invoked MSHTA — phishing payload from email",               "CRITICAL"),
    ],
    "chrome.exe": [
        ("powershell.exe", "Chrome spawned PowerShell — indicates browser exploit or injection","HIGH"),
        ("cmd.exe",        "Chrome opened CMD — unexpected browser child process",               "MEDIUM"),
        ("wscript.exe",    "Chrome invoked WScript — drive-by download script execution",       "HIGH"),
    ],
    "firefox.exe": [
        ("powershell.exe", "Firefox spawned PowerShell — browser-side exploit indicator",       "HIGH"),
        ("cmd.exe",        "Firefox opened CMD — atypical browser spawn behaviour",             "MEDIUM"),
    ],
    "msedge.exe": [
        ("powershell.exe", "Edge spawned PowerShell — possible browser vulnerability exploit",  "HIGH"),
    ],
    "mshta.exe": [
        ("powershell.exe", "MSHTA launched PowerShell — Living-off-the-Land (LotL) attack",    "CRITICAL"),
        ("cmd.exe",        "MSHTA invoked CMD — HTA-based malware stage execution",             "CRITICAL"),
        ("wscript.exe",    "MSHTA called WScript — chained scripting attack via HTA",           "CRITICAL"),
    ],
    "regsvr32.exe": [
        ("powershell.exe", "RegSvr32 spawned PowerShell — Squiblydoo bypass technique",        "CRITICAL"),
        ("cmd.exe",        "RegSvr32 opened CMD — suspicious COM scriptlet side-effect",        "CRITICAL"),
    ],
    "rundll32.exe": [
        ("powershell.exe", "RunDLL32 launched PowerShell — DLL side-loading pivot",            "HIGH"),
        ("cmd.exe",        "RunDLL32 opened CMD — unusual DLL execution pattern",               "HIGH"),
    ],
    "svchost.exe": [
        ("powershell.exe", "Service host launched PowerShell — potential service hijacking",    "HIGH"),
        ("cmd.exe",        "Service host opened CMD — abnormal Windows service behaviour",      "MEDIUM"),
    ],
    "explorer.exe": [
        ("powershell.exe", "Explorer spawned PowerShell — possible UAC bypass or injection",   "MEDIUM"),
    ],
}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _build_finding(proc: dict, severity: str, description: str) -> dict:
    """
    Construct a normalised finding dictionary from a process record.

    Parameters
    ----------
    proc        : dict   — process data dict from the collection layer.
    severity    : str    — one of INFO / LOW / MEDIUM / HIGH / CRITICAL.
    description : str    — plain-English explanation of the finding.

    Returns
    -------
    dict
        Finding record with keys: process, pid, parent, severity, reason,
        timestamp.
    """
    return {
        "process":   proc.get("name", "unknown"),
        "pid":       proc.get("pid", 0),
        "parent":    proc.get("parent_name", "unknown"),
        "severity":  severity,
        "reason":    description,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── Process assessment ────────────────────────────────────────────────────────

def assess_process(proc: dict) -> list:
    """
    Evaluate a single process record against all built-in detection rules.

    Rules evaluated (in order):
      1. Known-threat catalogue match → CRITICAL
      2. Executable located in a risky filesystem path → HIGH
      3. Unknown process with no executable path → MEDIUM
      4. Sustained CPU above the configured ceiling → MEDIUM

    Parameters
    ----------
    proc : dict
        Process record produced by the collection layer.  Expected keys:
        pid, name, path, ppid, parent_name, owner, cpu, memory.

    Returns
    -------
    list[dict]
        Zero or more finding dicts; empty list means the process is clean.
    """
    findings = []
    name     = (proc.get("name") or "").lower()
    path     = proc.get("path") or ""
    cpu      = proc.get("cpu") or 0.0

    # Rule 1 — Catalogued threat name
    if is_known_threat(name):
        findings.append(_build_finding(
            proc, "CRITICAL",
            f"Executable '{name}' matches the known-threat catalogue"
        ))

    # Rule 2 — Risky filesystem location
    for risky in _RISKY_PATHS:
        if risky.lower() in path.lower():
            findings.append(_build_finding(
                proc, "HIGH",
                f"Process launched from a high-risk directory: {path}"
            ))
            break

    # Rule 3 — Unrecognised process with no disk path
    if name and not is_trusted(name) and not is_known_threat(name):
        if not path:
            findings.append(_build_finding(
                proc, "MEDIUM",
                f"Unrecognised process '{name}' has no associated disk path"
            ))

    # Rule 4 — Excessive CPU consumption
    if cpu > _CPU_CEILING and not skip_cpu_check(name):
        findings.append(_build_finding(
            proc, "MEDIUM",
            f"'{name}' is consuming {cpu:.1f}% CPU (ceiling: {_CPU_CEILING}%)"
        ))

    return findings


# ── Spawn-chain assessment ────────────────────────────────────────────────────

def check_spawn_chain(parent_name: str, child_proc: dict) -> list:
    """
    Test a parent→child process relationship against PROC_SPAWN_RULES.

    Parameters
    ----------
    parent_name : str
        Name of the parent process (case-insensitive).
    child_proc  : dict
        Full process record of the child process.

    Returns
    -------
    list[dict]
        Finding dicts for each matched rule (usually zero or one).
    """
    findings     = []
    parent_lower = (parent_name or "").lower()
    child_lower  = (child_proc.get("name") or "").lower()

    for (suspected_child, description, severity) in PROC_SPAWN_RULES.get(parent_lower, []):
        if child_lower == suspected_child:
            finding           = _build_finding(child_proc, severity, description)
            finding["parent"] = parent_name
            findings.append(finding)

    return findings


# ── Service assessment ────────────────────────────────────────────────────────

def assess_service(svc: dict) -> tuple:
    """
    Evaluate a Windows service record for common misconfigurations and
    indicators of tampering.

    Checks performed:
      • Service binary located in a risky directory
      • Unquoted service path (privilege-escalation vector)
      • Service has no binary path at all

    Parameters
    ----------
    svc : dict
        Service record with keys: service_name, display_name, path, state,
        start_type.

    Returns
    -------
    tuple[bool, str, str]
        (is_suspicious, reason_string, severity_string)
    """
    raw_path  = svc.get("path") or ""
    path_lower = raw_path.lower()

    # Check 1 — Risky directory
    for risky in _RISKY_PATHS:
        if risky.lower() in path_lower:
            return (
                True,
                f"Service binary resides in a high-risk path: {raw_path}",
                "HIGH"
            )

    # Check 2 — Unquoted path containing spaces (privilege escalation)
    if " " in raw_path and not raw_path.startswith('"'):
        return (
            True,
            f"Service path is unquoted and contains spaces — privilege escalation risk: {raw_path}",
            "HIGH"
        )

    # Check 3 — Missing binary path
    if not raw_path:
        return (
            True,
            f"Service '{svc.get('service_name')}' has no registered binary path",
            "MEDIUM"
        )

    return False, "", "INFO"
