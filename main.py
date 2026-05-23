"""
main.py
SentinelEye — Endpoint Security Monitoring Agent
Entry point: bootstraps the database, executes the initial scan pipeline,
and launches the Tkinter GUI dashboard.

Usage:
    python main.py
    (Run as Administrator for full WMI and signature-check coverage)

Author  : Rohan Nair
Project : SentinelEye — Endpoint Monitoring Agent
"""

import os
import sys
import threading
import time
from datetime import datetime
from dataclasses import dataclass, field

# ── Ensure project root is importable ────────────────────────────────────────
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# ── Core utilities ────────────────────────────────────────────────────────────
from utils.helpers import is_admin, admin_privilege_warning, load_config
from utils.logger  import record_info, record_warning, record_error
from database      import db_manager

# ── Alert dispatch engine ────────────────────────────────────────────────────
from gui import alerts as alert_engine

# ── Collection layer ──────────────────────────────────────────────────────────
from monitor.process_monitor      import collect_running_processes
from monitor.service_monitor      import collect_system_services
from monitor.startup_monitor      import scan_startup_locations
from monitor.parent_child_analyzer import find_anomalous_spawn_chains, construct_proc_hierarchy
from monitor.anomaly_detector      import run_anomaly_sweep
from monitor.persistence_detector  import enumerate_persistence_vectors

# ── Detection layer ───────────────────────────────────────────────────────────
from detection.rules_engine import assess_process, assess_service

_CFG = load_config()


# ── Shared scan state ─────────────────────────────────────────────────────────

@dataclass
class ScanSnapshot:
    """Thread-safe container for the results of the most recent scan cycle."""
    processes:       list = field(default_factory=list)
    services:        list = field(default_factory=list)
    startup_entries: list = field(default_factory=list)
    alert_counts:    dict = field(default_factory=dict)
    alerts:          list = field(default_factory=list)
    scan_time:       str  = ""


_snapshot      = ScanSnapshot()
_snapshot_lock = threading.Lock()


# ── Severity ranking helper ───────────────────────────────────────────────────

def _level_rank(severity: str) -> int:
    """Map a severity string to an integer for comparison purposes."""
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(severity, 0)


def retrieve_scan_snapshot() -> dict:
    """Return a plain dict copy of the latest scan snapshot (thread-safe)."""
    with _snapshot_lock:
        return {
            "processes":       _snapshot.processes,
            "services":        _snapshot.services,
            "startup_entries": _snapshot.startup_entries,
            "alert_counts":    _snapshot.alert_counts,
            "alerts":          _snapshot.alerts,
            "scan_time":       _snapshot.scan_time,
        }


# ═════════════════════════════════════════════════════════════════════════════
# SCAN ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════

class ScanOrchestrator:
    """
    Coordinates the full SentinelEye scan pipeline in a defined sequence:

      1.  Enumerate running processes
      2.  Enumerate installed services
      3.  Enumerate persistence / startup entries
      4.  Resolve parent-child spawn relationships
      5.  Detect suspicious spawn chains
      6.  Apply per-process detection rules
      7.  Run anomaly-detection sweep
      8.  Apply per-service detection rules
      9.  Persist results to the SQLite database
      10. Dispatch all generated findings to the alert engine
      11. Update the shared scan snapshot for GUI consumption

    A threading lock ensures only one scan cycle runs at a time — if the
    previous scan has not finished when the next trigger fires, the new
    request is silently skipped to prevent thread pile-up and DB contention.
    """

    def __init__(self) -> None:
        self._running = threading.Lock()

    def execute(self) -> None:
        """
        Run a complete scan cycle and update the shared snapshot.
        If a scan is already in progress this call returns immediately.
        """
        if not self._running.acquire(blocking=False):
            record_info("[SCAN] Previous cycle still running — skipping this trigger")
            return
        try:
            self._run_cycle()
        finally:
            self._running.release()

    def _run_cycle(self) -> None:
        """Internal: execute the full pipeline (called under the scan lock)."""
        cycle_start = datetime.now()
        record_info(
            f"[SCAN] Cycle started at {cycle_start.strftime('%Y-%m-%d %H:%M:%S')}"
        )

        # Step 1 — Processes
        try:
            processes = collect_running_processes()
            record_info(f"[SCAN] {len(processes)} processes enumerated")
        except Exception as exc:
            record_error(f"[SCAN] Process collection failed: {exc}")
            processes = []

        # Step 2 — Services
        try:
            services = collect_system_services()
            record_info(f"[SCAN] {len(services)} services audited")
        except Exception as exc:
            record_error(f"[SCAN] Service collection failed: {exc}")
            services = []

        # Step 3 — Persistence / startup entries
        try:
            persistence_entries = enumerate_persistence_vectors()
            record_info(f"[SCAN] {len(persistence_entries)} persistence entries found")
        except Exception as exc:
            record_error(f"[SCAN] Persistence scan failed: {exc}")
            persistence_entries = []

        # Steps 4–5 — Parent-child hierarchy and suspicious spawn chains
        spawn_findings = []
        try:
            spawn_findings = find_anomalous_spawn_chains(processes)
            record_info(f"[SCAN] {len(spawn_findings)} suspicious spawn chains detected")
        except Exception as exc:
            record_error(f"[SCAN] Spawn-chain analysis failed: {exc}")

        # Step 6 — Per-process rule evaluation
        proc_findings = []
        for proc in processes:
            try:
                hits = assess_process(proc)
                if hits:
                    top = max(hits, key=lambda h: _level_rank(h["severity"]))
                    proc["severity"] = top["severity"]
                    proc["reason"]   = top["reason"]
                proc_findings.extend(hits)
            except Exception:
                pass

        # Step 7 — Anomaly sweep
        anomaly_findings = []
        try:
            anomaly_findings = run_anomaly_sweep(processes)
            record_info(f"[SCAN] {len(anomaly_findings)} anomaly findings raised")
        except Exception as exc:
            record_error(f"[SCAN] Anomaly sweep failed: {exc}")

        # Step 8 — Per-service rule evaluation
        for svc in services:
            try:
                flagged, reason, sev = assess_service(svc)
                if flagged:
                    svc["is_suspicious"] = 1
                    svc["reason"]        = reason
            except Exception:
                pass

        # Step 9 — Persist to database
        try:
            db_manager.wipe_table("processes")
            for p in processes:
                db_manager.store_process(p)

            db_manager.wipe_table("services")
            for s in services:
                db_manager.store_service(s)

            db_manager.wipe_table("startup_entries")
            for e in persistence_entries:
                db_manager.store_startup_entry(e)
        except Exception as exc:
            record_error(f"[DB] Write failure: {exc}")

        # Step 10 — Dispatch all findings
        all_findings = spawn_findings + proc_findings + anomaly_findings

        # Also raise findings for suspicious persistence entries
        for entry in persistence_entries:
            if entry.get("is_suspicious"):
                all_findings.append({
                    "process":   entry.get("name", ""),
                    "pid":       0,
                    "parent":    entry.get("source", ""),
                    "severity":  "HIGH",
                    "reason":    entry.get("reason", ""),
                })

        alert_engine.dispatch_findings(all_findings)
        record_info(f"[SCAN] {len(all_findings)} findings dispatched this cycle")

        # Step 11 — Update shared snapshot
        with _snapshot_lock:
            _snapshot.processes       = processes
            _snapshot.services        = services
            _snapshot.startup_entries = persistence_entries
            _snapshot.alert_counts    = alert_engine.tally_by_level()
            _snapshot.alerts          = alert_engine.fetch_all_findings()
            _snapshot.scan_time       = cycle_start.strftime("%Y-%m-%d %H:%M:%S")

        elapsed = (datetime.now() - cycle_start).total_seconds()
        record_info(f"[SCAN] Cycle completed in {elapsed:.2f}s")


# ═════════════════════════════════════════════════════════════════════════════
# APPLICATION ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    # Reconfigure stdout to UTF-8 on Windows terminals that default to cp1252
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("=" * 68)
    print("  [*] SentinelEye — Endpoint Security Monitoring Agent")
    print("  Author : Rohan Nair")
    print("=" * 68)

    # Privilege check
    priv_warning = admin_privilege_warning()
    if priv_warning:
        record_warning(priv_warning)
        print(f"\n{priv_warning}\n")
    else:
        print("[OK] Running as Administrator — full monitoring coverage active\n")

    # Bootstrap the database schema
    db_manager.bootstrap_schema()
    record_info("SentinelEye database schema initialised")

    # Instantiate the scan orchestrator and run the first cycle synchronously
    orchestrator = ScanOrchestrator()
    print("[>>] Running initial scan…")
    first_scan = threading.Thread(target=orchestrator.execute, daemon=True)
    first_scan.start()
    first_scan.join(timeout=30)  # give the first scan up to 30 s before opening GUI

    # Launch the GUI
    print("[>>] Opening SentinelEye dashboard…\n")
    from gui.dashboard import SentinelEyeApp
    app = SentinelEyeApp(
        scan_data_getter=retrieve_scan_snapshot,
        scan_trigger=orchestrator.execute,
    )
    app.mainloop()


if __name__ == "__main__":
    main()
