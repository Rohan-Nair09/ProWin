"""
monitor/service_monitor.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import os
from datetime import datetime
from detection.rules_engine import assess_service

# Windows services whose unexpected absence or stopped state is a red flag
CRITICAL_SERVICES: set = {
    "windefend",            # Windows Defender antivirus
    "wscsvc",               # Windows Security Centre
    "mpssvc",               # Windows Firewall
    "eventlog",             # Event Logging service
    "bits",                 # Background Intelligent Transfer Service
    "wuauserv",             # Windows Update
    "securityhealthservice",# Security Health Agent
}


def _assemble_service_record(
    name:         str,
    display_name: str,
    path:         str,
    state:        str,
    start_type:   str,
) -> dict:
    """
    Build a normalised service record dict and run it through the rule engine.

    Additionally flags any critical security service found in a stopped state,
    which may indicate deliberate tampering to disable defences.

    Parameters
    ----------
    name         : str — Short service name (e.g. 'windefend').
    display_name : str — User-visible service description.
    path         : str — Binary path of the service executable.
    state        : str — Current state ('Running', 'Stopped', etc.).
    start_type   : str — Startup mode ('Auto', 'Manual', 'Disabled', etc.).

    Returns
    -------
    dict
        Normalised service record with is_suspicious and reason populated.
    """
    record = {
        "service_name": name,
        "display_name": display_name,
        "path":         path,
        "state":        state,
        "start_type":   start_type,
        "is_suspicious": 0,
        "reason":       "",
        "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    flagged, reason, _ = assess_service(record)

    # Additional check: a known-critical security service in a stopped state
    if name.lower() in CRITICAL_SERVICES and state.lower() == "stopped":
        flagged = True
        reason  = (
            f"Critical security service '{name}' is currently STOPPED — "
            "possible security tool tampering"
        )

    record["is_suspicious"] = 1 if flagged else 0
    record["reason"]        = reason
    return record


def _query_sc_exe() -> list:
    """
    Enumerate services using the sc.exe command-line tool when WMI is
    unavailable.  Extracts service names and states from the structured output.

    Returns
    -------
    list[dict]
        Minimal service records (display_name and path will be empty).
    """
    import subprocess

    records = []
    try:
        proc = subprocess.run(
            ["sc", "query", "type=", "all", "state=", "all"],
            capture_output=True, text=True, timeout=15
        )
        current: dict = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                current = {
                    "service_name": line.split(":", 1)[1].strip(),
                    "display_name": "",
                    "path":         "",
                    "state":        "",
                    "start_type":   "",
                    "is_suspicious": 0,
                    "reason":       "",
                    "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            elif line.startswith("STATE") and current:
                parts = line.split(":")
                if len(parts) > 1:
                    tokens = parts[1].strip().split()
                    current["state"] = tokens[1] if len(tokens) > 1 else ""
                records.append(current)
                current = {}
    except Exception:
        pass
    return records


def collect_system_services() -> list:
    """
    Return a complete audit list of all Windows services on the local machine.

    Attempts WMI-based enumeration first; if WMI raises any exception (e.g.
    not running as Administrator, WMI service stopped), falls back to parsing
    sc.exe output.

    Returns
    -------
    list[dict]
        Each element is a normalised service record with keys:
        service_name, display_name, path, state, start_type,
        is_suspicious, reason, timestamp.
    """
    services = []

    try:
        import wmi
        wmi_conn = wmi.WMI()
        for svc in wmi_conn.Win32_Service():
            record = _assemble_service_record(
                name         = svc.Name        or "",
                display_name = svc.DisplayName or "",
                path         = svc.PathName    or "",
                state        = svc.State       or "",
                start_type   = svc.StartMode   or "",
            )
            services.append(record)

    except Exception:
        # WMI unavailable — use sc.exe fallback
        services = _query_sc_exe()

    return services
