"""
monitor/process_monitor.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import psutil
from datetime import datetime
from utils.helpers import resolve_proc_owner, humanize_size


def _gather_raw_procs() -> list:
    """
    First-pass collection: iterate over all live processes and capture
    available attributes.  CPU percentage is sampled non-blocking; two
    successive samples would give a more accurate figure but introduce
    unacceptable latency when hundreds of processes are present.

    Returns
    -------
    list[dict]
        Partially-populated process records (parent_name left empty).
    """
    raw = []
    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "cmdline",
         "username", "status", "memory_info"]
    ):
        try:
            info = proc.info

            try:
                cpu_pct = proc.cpu_percent(interval=None)
            except Exception:
                cpu_pct = 0.0

            mem_info  = info.get("memory_info")
            mem_bytes = mem_info.rss if mem_info else 0

            raw.append({
                "pid":         info.get("pid", 0),
                "ppid":        info.get("ppid", 0),
                "name":        info.get("name") or "Unknown",
                "path":        info.get("exe") or "",
                "cmdline":     " ".join(info.get("cmdline") or []),
                "owner":       info.get("username") or resolve_proc_owner(proc),
                "cpu":         cpu_pct,
                "memory":      mem_bytes,
                "memory_str":  humanize_size(mem_bytes),
                "status":      info.get("status") or "unknown",
                "parent_name": "",          # resolved in second pass
                "severity":    "INFO",      # filled by rules engine
                "reason":      "",
                "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process terminated between enumeration and attribute access
            continue

    return raw


def _resolve_parent_names(procs: list) -> None:
    """
    Second-pass in-place update: fill the parent_name field of each record
    by looking up the parent PID in the already-collected process list.
    Unknown parents are labelled 'Unknown'.

    Parameters
    ----------
    procs : list[dict]
        Process records from _gather_raw_procs(); modified in-place.
    """
    pid_to_name = {p["pid"]: p["name"] for p in procs}
    for p in procs:
        p["parent_name"] = pid_to_name.get(p["ppid"], "Unknown")


def collect_running_processes() -> list:
    """
    Return a fully-populated snapshot of all currently running processes.

    The function performs two enumeration passes:
      1. Collect raw attributes from psutil.
      2. Back-fill parent process names using the collected PID→name map.

    Returns
    -------
    list[dict]
        Each element is a process snapshot dict with the following keys:
        pid, ppid, name, path, cmdline, owner, cpu, memory, memory_str,
        status, parent_name, severity, reason, timestamp.
    """
    procs = _gather_raw_procs()
    _resolve_parent_names(procs)
    return procs


def fetch_process_info(pid: int) -> dict | None:
    """
    Retrieve a single process snapshot for the given *pid*.

    Parameters
    ----------
    pid : int
        Target process identifier.

    Returns
    -------
    dict | None
        Process snapshot dict, or None if the PID does not exist or is
        inaccessible.
    """
    try:
        proc = psutil.Process(pid)
        info = proc.as_dict(
            attrs=["pid", "ppid", "name", "exe", "cmdline",
                   "username", "status", "memory_info", "cpu_percent"]
        )
        mem_info = info.get("memory_info")
        mem_bytes = mem_info.rss if mem_info else 0

        return {
            "pid":        info["pid"],
            "ppid":       info.get("ppid", 0),
            "name":       info.get("name") or "Unknown",
            "path":       info.get("exe") or "",
            "cmdline":    " ".join(info.get("cmdline") or []),
            "owner":      info.get("username") or "N/A",
            "cpu":        info.get("cpu_percent") or 0.0,
            "memory":     mem_bytes,
            "memory_str": humanize_size(mem_bytes),
            "status":     info.get("status") or "unknown",
            "parent_name": "",
        }
    except Exception:
        return None
