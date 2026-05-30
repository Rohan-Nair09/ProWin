"""
monitor/persistence_detector.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import subprocess
from datetime import datetime
from monitor.startup_monitor import scan_startup_locations


# ── Scheduled Task harvester ──────────────────────────────────────────────────

def _harvest_scheduled_tasks() -> list:
    """
    Enumerate all Windows Scheduled Tasks using schtasks.exe with CSV output
    and identify entries that show indicators of malicious persistence.

    Suspicious indicators evaluated:
      • Task binary runs from a temporary or user-writable directory.
      • Task runs under the SYSTEM account but is not a Microsoft-authored task.

    Returns
    -------
    list[dict]
        One entry dict per scheduled task row parsed from schtasks output.
    """
    task_entries = []
    try:
        proc_result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=20,
            encoding="utf-8",
            errors="replace",
        )

        lines = proc_result.stdout.splitlines()
        if not lines:
            return task_entries

        # Parse the CSV header row
        column_headers = [col.strip().strip('"') for col in lines[0].split(",")]

        for raw_line in lines[1:]:
            columns = [col.strip().strip('"') for col in raw_line.split(",")]
            if len(columns) < len(column_headers):
                continue

            row = dict(zip(column_headers, columns))

            task_name    = row.get("TaskName", "")
            task_binary  = row.get("Task To Run", "")
            run_as_user  = row.get("Run As User", "")

            flagged = False
            rationale = ""

            # Indicator 1: executable in a risky temp/writable location
            risky_segments = ["\\Temp\\", "\\tmp\\", "\\AppData\\Local\\Temp\\"]
            for segment in risky_segments:
                if segment.lower() in task_binary.lower():
                    flagged   = True
                    rationale = f"Scheduled task binary located in temporary path: {task_binary}"
                    break

            # Indicator 2: non-Microsoft task executing as SYSTEM
            if "SYSTEM" in run_as_user.upper() and task_name.startswith("\\"):
                if "\\Microsoft\\" not in task_name:
                    flagged   = True
                    rationale = rationale or (
                        f"Non-Microsoft scheduled task running as SYSTEM: {task_name}"
                    )

            task_entries.append({
                "name":          task_name,
                "path":          task_binary,
                "source":        "Scheduled Task",
                "is_suspicious": 1 if flagged else 0,
                "reason":        rationale,
                "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

    except Exception:
        pass

    return task_entries


# ── Public interface ──────────────────────────────────────────────────────────

def enumerate_persistence_vectors() -> list:
    """
    Collect all persistence entries from every supported mechanism:
      1. HKCU/HKLM Run and RunOnce registry keys
      2. User and all-users shell:startup folders
      3. Windows Scheduled Tasks

    Returns
    -------
    list[dict]
        Combined list of persistence entry records ready for the scan pipeline.
    """
    entries = scan_startup_locations()
    entries.extend(_harvest_scheduled_tasks())
    return entries
