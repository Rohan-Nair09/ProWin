"""
monitor/anomaly_detector.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

from collections import Counter
from datetime import datetime
from utils.helpers import load_config
from detection.whitelist import allows_multi_copy, skip_cpu_check

_CFG         = load_config()
_CPU_CEILING = _CFG.get("cpu_alert_threshold", 80.0)

# Windows processes that are expected to have exactly ONE running instance
# (excluding the special multi-copy allowances in whitelist.py).
SINGLETON_PROCS: set = {
    "lsass.exe",    # Local Security Authority process
    "winlogon.exe", # Windows logon manager
    "wininit.exe",  # Windows initialisation
    "csrss.exe",    # Client/Server Runtime Subsystem (note: per-session but limited)
    "smss.exe",     # Session Manager Subsystem
    "services.exe", # Service Control Manager
    "spoolsv.exe",  # Print Spooler
    "lsm.exe",      # Local Session Manager
}


def flag_ghost_duplicates(processes: list) -> list:
    """
    Identify processes that run as multiple simultaneous instances when only
    one is expected.  This pattern is consistent with process name masquerading
    and process hollowing attacks.

    Parameters
    ----------
    processes : list[dict]
        Full process snapshot from the collection layer.

    Returns
    -------
    list[dict]
        Finding dicts for each unexpected duplicate detected.
    """
    findings      = []
    instance_count = Counter(p["name"].lower() for p in processes)

    for proc in processes:
        name_lower = proc["name"].lower()
        if (
            name_lower in SINGLETON_PROCS
            and instance_count[name_lower] > 1
            and not allows_multi_copy(name_lower)
        ):
            findings.append({
                "process":   proc["name"],
                "pid":       proc["pid"],
                "parent":    proc.get("parent_name", ""),
                "severity":  "HIGH",
                "reason":    (
                    f"'{proc['name']}' has {instance_count[name_lower]} running instances "
                    "— consistent with process-name masquerading or hollowing"
                ),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

    return findings


def flag_pathless_procs(processes: list) -> list:
    """
    Flag user-space processes that have no associated executable path on disk.
    Legitimate processes always have a backing file; a missing path strongly
    suggests process hollowing or code injection.

    Parameters
    ----------
    processes : list[dict]
        Full process snapshot from the collection layer.

    Returns
    -------
    list[dict]
        Finding dicts for each pathless process above PID 4.
    """
    findings = []
    for proc in processes:
        name = proc.get("name", "")
        path = proc.get("path", "")
        # Skip PID 0 (Idle) and PID 4 (System) — they never have paths
        if name and not path and proc.get("pid", 0) > 4:
            findings.append({
                "process":   name,
                "pid":       proc["pid"],
                "parent":    proc.get("parent_name", ""),
                "severity":  "MEDIUM",
                "reason":    (
                    f"Process '{name}' has no backing executable on disk — "
                    "possible code injection or memory-only execution"
                ),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
    return findings


def flag_cpu_hogs(processes: list) -> list:
    """
    Identify processes whose CPU utilisation exceeds the configured ceiling.
    Persistent high CPU is associated with crypto-mining and CPU-bound denial
    of service scenarios.

    Parameters
    ----------
    processes : list[dict]
        Full process snapshot from the collection layer.

    Returns
    -------
    list[dict]
        Finding dicts for processes breaching the CPU threshold.
    """
    findings = []
    for proc in processes:
        cpu_usage = proc.get("cpu", 0.0) or 0.0
        proc_name = proc.get("name", "").lower()
        if cpu_usage > _CPU_CEILING and not skip_cpu_check(proc_name):
            findings.append({
                "process":   proc.get("name", ""),
                "pid":       proc.get("pid", 0),
                "parent":    proc.get("parent_name", ""),
                "severity":  "MEDIUM",
                "reason":    (
                    f"CPU usage at {cpu_usage:.1f}% exceeds the "
                    f"configured ceiling of {_CPU_CEILING}%"
                ),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
    return findings


def run_anomaly_sweep(processes: list) -> list:
    """
    Execute all three anomaly-detection checks and return a combined finding
    list.

    Parameters
    ----------
    processes : list[dict]
        Full process snapshot from the collection layer.

    Returns
    -------
    list[dict]
        Combined findings from duplicate, pathless, and high-CPU detectors.
    """
    results = []
    results.extend(flag_ghost_duplicates(processes))
    results.extend(flag_pathless_procs(processes))
    results.extend(flag_cpu_hogs(processes))
    return results
