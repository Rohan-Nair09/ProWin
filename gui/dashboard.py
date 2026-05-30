"""
gui/dashboard.py
Project : ProWin - Windows Service & Process Monitoring Agent
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import os
from datetime import datetime

from gui import alerts as alert_engine
from gui.statistics import build_bar_chart, build_pie_chart, build_process_graph
from utils.helpers import is_admin, level_to_hex, level_to_bg_hex, humanize_size, load_config

_CFG = load_config()

# ── Colour palette ────────────────────────────────────────────────────────────
PALETTE = {
    "bg":        "#1e1e2e",
    "panel":     "#24273a",
    "panel2":    "#2a2a3e",
    "border":    "#313244",
    "accent":    "#89b4fa",
    "accent2":   "#cba6f7",
    "text":      "#cdd6f4",
    "subtext":   "#a6adc8",
    "red":       "#f38ba8",
    "green":     "#a6e3a1",
    "yellow":    "#f9e2af",
    "orange":    "#fab387",
    "teal":      "#94e2d5",
    "topbar":    "#181825",
}

FONT_BODY  = ("Segoe UI", 9)
FONT_BOLD  = ("Segoe UI Semibold", 9)
FONT_TITLE = ("Segoe UI", 13, "bold")
FONT_MONO  = ("Consolas", 8)


# ═════════════════════════════════════════════════════════════════════════════
class SentinelEyeApp(tk.Tk):
    """
    Primary application window for ProWin.

    Accepts two callables injected at construction time so the GUI remains
    decoupled from the scan pipeline:
      scan_data_getter — returns the latest scan results dict.
      scan_trigger     — initiates a fresh full scan.
    """

    def __init__(self, scan_data_getter, scan_trigger):
        super().__init__()

        self._get_scan_data    = scan_data_getter
        self._trigger_scan     = scan_trigger
        self._latest_data: dict = {}
        self._auto_refresh     = tk.BooleanVar(value=True)
        self._poll_interval    = _CFG.get("refresh_interval_sec", 10)
        self._search_term      = tk.StringVar()
        self._search_term.trace_add("write", self._on_search_updated)

        self.title("🔍 ProWin — Windows Service & Process Monitoring Agent")
        self.geometry("1280x800")
        self.minsize(1100, 700)
        self.configure(bg=PALETTE["bg"])

        self._apply_visual_theme()
        self._compose_layout()
        self._launch_refresh_loop()

        alert_engine.bind_ui_hook(self._handle_new_finding)

    # ── Theme ──────────────────────────────────────────────────────────────────

    def _apply_visual_theme(self) -> None:
        """Apply the ProWin dark colour scheme to all ttk widgets."""
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".",
            background=PALETTE["bg"],
            foreground=PALETTE["text"],
            font=FONT_BODY,
            borderwidth=0,
        )
        style.configure("TFrame", background=PALETTE["bg"])
        style.configure("TLabel", background=PALETTE["bg"], foreground=PALETTE["text"])

        style.configure("TButton",
            background=PALETTE["panel2"],
            foreground=PALETTE["text"],
            relief="flat",
            padding=(10, 5),
            font=FONT_BOLD,
        )
        style.map("TButton",
            background=[("active", PALETTE["accent"]), ("pressed", PALETTE["accent2"])],
            foreground=[("active", PALETTE["bg"])],
        )
        style.configure("Accent.TButton",
            background=PALETTE["accent"],
            foreground=PALETTE["bg"],
            font=FONT_BOLD,
            relief="flat",
            padding=(12, 6),
        )
        style.map("Accent.TButton",
            background=[("active", PALETTE["accent2"])],
        )

        style.configure("TNotebook", background=PALETTE["topbar"], borderwidth=0)
        style.configure("TNotebook.Tab",
            background=PALETTE["panel"],
            foreground=PALETTE["subtext"],
            padding=(14, 7),
            font=FONT_BOLD,
        )
        style.map("TNotebook.Tab",
            background=[("selected", PALETTE["bg"])],
            foreground=[("selected", PALETTE["accent"])],
        )

        style.configure("Treeview",
            background=PALETTE["panel"],
            foreground=PALETTE["text"],
            fieldbackground=PALETTE["panel"],
            rowheight=24,
            font=FONT_MONO,
            borderwidth=0,
        )
        style.configure("Treeview.Heading",
            background=PALETTE["topbar"],
            foreground=PALETTE["accent"],
            font=FONT_BOLD,
            relief="flat",
            borderwidth=0,
        )
        style.map("Treeview",
            background=[("selected", PALETTE["accent2"])],
            foreground=[("selected", PALETTE["bg"])],
        )

        style.configure("TEntry",
            fieldbackground=PALETTE["panel2"],
            foreground=PALETTE["text"],
            insertcolor=PALETTE["text"],
            relief="flat",
            padding=(6, 4),
        )
        style.configure("TScrollbar",
            background=PALETTE["panel"],
            troughcolor=PALETTE["bg"],
            arrowcolor=PALETTE["subtext"],
        )

    # ── Layout assembly ────────────────────────────────────────────────────────

    def _compose_layout(self) -> None:
        """Assemble the top bar, notebook tabs, and status bar."""
        self._render_topbar()
        if not is_admin():
            self._render_privilege_banner()

        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._tab_procs   = self._init_process_panel()
        self._tab_svcs    = self._init_service_panel()
        self._tab_alerts  = self._init_alert_panel()
        self._tab_startup = self._init_startup_panel()
        self._tab_stats   = self._init_stats_panel()
        self._tab_graph   = self._init_graph_panel()

        self._notebook.add(self._tab_procs,   text="  ⚙  Processes   ")
        self._notebook.add(self._tab_svcs,    text="  🔧  Services    ")
        self._notebook.add(self._tab_alerts,  text="  🚨  Findings    ")
        self._notebook.add(self._tab_startup, text="  📌  Startup Apps ")
        self._notebook.add(self._tab_stats,   text="  📊  Statistics  ")
        self._notebook.add(self._tab_graph,   text="  🌲  Process Map ")

        self._render_statusbar()

    def _render_topbar(self) -> None:
        """Build the header bar with branding, search, and action buttons."""
        topbar = tk.Frame(self, bg=PALETTE["topbar"], height=60)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        tk.Label(
            topbar, text="🔍  ProWin",
            font=("Segoe UI", 15, "bold"),
            bg=PALETTE["topbar"], fg=PALETTE["accent"],
        ).pack(side="left", padx=18, pady=12)

        tk.Label(
            topbar, text="Prowin: Windows Service & Process Monitoring Agent  |  Author: Rohan Nair",
            font=("Segoe UI", 9),
            bg=PALETTE["topbar"], fg=PALETTE["subtext"],
        ).pack(side="left", pady=12)

        # Right-side controls
        controls = tk.Frame(topbar, bg=PALETTE["topbar"])
        controls.pack(side="right", padx=16)

        ttk.Button(
            controls, text="⟳  Scan Now",
            style="Accent.TButton",
            command=self._trigger_manual_scan,
        ).pack(side="right", padx=6, pady=10)

        ttk.Button(
            controls, text="📄  Export Report",
            command=self._save_report,
        ).pack(side="right", padx=2, pady=10)

        # Search bar
        search_row = tk.Frame(topbar, bg=PALETTE["topbar"])
        search_row.pack(side="right", padx=10, pady=10)
        tk.Label(
            search_row, text="🔍", bg=PALETTE["topbar"], fg=PALETTE["subtext"]
        ).pack(side="left")
        ttk.Entry(search_row, textvariable=self._search_term, width=22).pack(side="left", padx=4)

        # Auto-refresh toggle
        tk.Checkbutton(
            controls, text="Auto Refresh",
            variable=self._auto_refresh,
            bg=PALETTE["topbar"], fg=PALETTE["subtext"],
            selectcolor=PALETTE["panel"],
            activebackground=PALETTE["topbar"],
            font=FONT_BODY,
        ).pack(side="right", padx=8)

    def _render_privilege_banner(self) -> None:
        """Display a warning strip when ProWin lacks Administrator rights."""
        banner = tk.Frame(self, bg="#3d1a1a", height=30)
        banner.pack(fill="x")
        banner.pack_propagate(False)
        tk.Label(
            banner,
            text=(
                "⚠  Running without Administrator privileges — "
                "WMI service queries, process owners, and signature checks are limited. "
                "Right-click → Run as administrator for full coverage."
            ),
            bg="#3d1a1a", fg=PALETTE["red"], font=FONT_BODY,
        ).pack(side="left", padx=16)

    def _render_statusbar(self) -> None:
        """Build the status bar at the bottom of the window."""
        bar = tk.Frame(self, bg=PALETTE["topbar"], height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._lbl_status = tk.Label(
            bar, text="Initialising…",
            bg=PALETTE["topbar"], fg=PALETTE["subtext"],
            font=("Segoe UI", 8), anchor="w",
        )
        self._lbl_status.pack(side="left", padx=12)

        self._lbl_finding_count = tk.Label(
            bar, text="Findings: 0",
            bg=PALETTE["topbar"], fg=PALETTE["yellow"],
            font=("Segoe UI Semibold", 8),
        )
        self._lbl_finding_count.pack(side="right", padx=12)

        self._lbl_scan_ts = tk.Label(
            bar, text="",
            bg=PALETTE["topbar"], fg=PALETTE["subtext"],
            font=("Segoe UI", 8),
        )
        self._lbl_scan_ts.pack(side="right", padx=18)

    # ── Process panel ──────────────────────────────────────────────────────────

    def _init_process_panel(self) -> ttk.Frame:
        frame   = ttk.Frame(self._notebook)
        cols    = ("pid", "name", "path", "owner", "cpu", "memory", "severity", "parent")
        headers = ("PID", "Process Name", "Executable Path", "Owner",
                   "CPU %", "Memory", "Severity", "Parent")
        widths  = (55, 140, 300, 110, 60, 80, 80, 120)

        self._tbl_procs, _ = self._create_data_table(frame, cols, headers, widths)
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self._tbl_procs.tag_configure(level, foreground=level_to_hex(level))
        return frame

    def _refresh_process_rows(self, processes: list) -> None:
        """Repopulate the process table, applying the active search filter."""
        query = self._search_term.get().lower()
        self._tbl_procs.delete(*self._tbl_procs.get_children())
        for p in processes:
            if query and (
                query not in str(p.get("name", "")).lower()
                and query not in str(p.get("path", "")).lower()
            ):
                continue
            lvl = p.get("severity", "INFO")
            self._tbl_procs.insert("", "end", tags=(lvl,), values=(
                p.get("pid", ""),
                p.get("name", ""),
                p.get("path", "") or "—",
                p.get("owner", ""),
                f"{p.get('cpu', 0):.1f}",
                p.get("memory_str", ""),
                lvl,
                p.get("parent_name", ""),
            ))

    # ── Service panel ──────────────────────────────────────────────────────────

    def _init_service_panel(self) -> ttk.Frame:
        frame   = ttk.Frame(self._notebook)
        cols    = ("name", "display", "state", "start", "flagged", "reason")
        headers = ("Service Name", "Display Name", "State", "Start Type",
                   "Suspicious", "Reason")
        widths  = (160, 200, 80, 90, 80, 350)
        self._tbl_svcs, _ = self._create_data_table(frame, cols, headers, widths)
        self._tbl_svcs.tag_configure("flagged", foreground=PALETTE["orange"])
        self._tbl_svcs.tag_configure("clean",   foreground=PALETTE["green"])
        return frame

    def _refresh_service_rows(self, services: list) -> None:
        """Repopulate the service table with the latest scan results."""
        query = self._search_term.get().lower()
        self._tbl_svcs.delete(*self._tbl_svcs.get_children())
        for s in services:
            if query and query not in str(s.get("service_name", "")).lower():
                continue
            is_flagged = s.get("is_suspicious", 0)
            tag = "flagged" if is_flagged else "clean"
            self._tbl_svcs.insert("", "end", tags=(tag,), values=(
                s.get("service_name", ""),
                s.get("display_name", ""),
                s.get("state", ""),
                s.get("start_type", ""),
                "⚠ YES" if is_flagged else "✅ No",
                s.get("reason", "") or "",
            ))

    # ── Alert / Findings panel ─────────────────────────────────────────────────

    def _init_alert_panel(self) -> ttk.Frame:
        frame = ttk.Frame(self._notebook)

        # Severity filter bar
        filter_row = tk.Frame(frame, bg=PALETTE["bg"])
        filter_row.pack(fill="x", padx=8, pady=6)
        tk.Label(
            filter_row, text="Filter by severity:",
            bg=PALETTE["bg"], fg=PALETTE["subtext"], font=FONT_BOLD,
        ).pack(side="left")

        self._finding_filter = tk.StringVar(value="ALL")
        for sev in ("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            colour = level_to_hex(sev) if sev != "ALL" else PALETTE["accent"]
            tk.Radiobutton(
                filter_row, text=sev,
                variable=self._finding_filter, value=sev,
                bg=PALETTE["bg"], fg=colour,
                selectcolor=PALETTE["panel2"],
                activebackground=PALETTE["bg"],
                font=FONT_BOLD,
                command=self._redraw_finding_rows,
            ).pack(side="left", padx=6)

        ttk.Button(
            filter_row, text="🗑 Clear",
            command=self._clear_all_findings,
        ).pack(side="right", padx=4)

        cols    = ("ts", "process", "pid", "parent", "severity", "reason")
        headers = ("Timestamp", "Process", "PID", "Parent", "Severity", "Reason")
        widths  = (130, 130, 55, 130, 80, 500)
        self._tbl_alerts, _ = self._create_data_table(frame, cols, headers, widths)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self._tbl_alerts.tag_configure(sev, foreground=level_to_hex(sev))
        return frame

    def _redraw_finding_rows(self) -> None:
        """Rebuild the findings table applying the active severity filter."""
        active_filter = self._finding_filter.get()
        all_findings  = alert_engine.fetch_all_findings()
        if active_filter != "ALL":
            all_findings = [f for f in all_findings if f.get("severity", "") == active_filter]

        self._tbl_alerts.delete(*self._tbl_alerts.get_children())
        for f in reversed(all_findings):
            sev = f.get("severity", "INFO")
            self._tbl_alerts.insert("", "end", tags=(sev,), values=(
                f.get("timestamp", "")[:16],
                f.get("process", ""),
                f.get("pid", ""),
                f.get("parent", ""),
                sev,
                f.get("reason", ""),
            ))

        counts = alert_engine.tally_by_level()
        total  = sum(counts.values())
        self._lbl_finding_count.config(
            text=(
                f"Findings: {total}  |  "
                f"CRIT:{counts.get('CRITICAL', 0)}  "
                f"HIGH:{counts.get('HIGH', 0)}"
            )
        )

    def _clear_all_findings(self) -> None:
        alert_engine.flush_findings()
        self._redraw_finding_rows()

    # ── Startup / Persistence panel ────────────────────────────────────────────

    def _init_startup_panel(self) -> ttk.Frame:
        frame   = ttk.Frame(self._notebook)
        cols    = ("name", "source", "path", "flagged", "reason")
        headers = ("Entry Name", "Source", "Path", "Suspicious", "Reason")
        widths  = (160, 130, 330, 80, 380)
        self._tbl_startup, _ = self._create_data_table(frame, cols, headers, widths)
        self._tbl_startup.tag_configure("flagged", foreground=PALETTE["orange"])
        self._tbl_startup.tag_configure("clean",   foreground=PALETTE["green"])
        return frame

    def _refresh_startup_rows(self, entries: list) -> None:
        """Repopulate the persistence/startup entries table."""
        self._tbl_startup.delete(*self._tbl_startup.get_children())
        for e in entries:
            is_flagged = e.get("is_suspicious", 0)
            tag = "flagged" if is_flagged else "clean"
            self._tbl_startup.insert("", "end", tags=(tag,), values=(
                e.get("name", ""),
                e.get("source", ""),
                e.get("path", ""),
                "⚠ YES" if is_flagged else "✅ No",
                e.get("reason", "") or "",
            ))

    # ── Statistics panel ───────────────────────────────────────────────────────

    def _init_stats_panel(self) -> ttk.Frame:
        frame = ttk.Frame(self._notebook)
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(0, weight=1)

        self._chart_bar_host = tk.Frame(frame, bg=PALETTE["bg"])
        self._chart_bar_host.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        self._chart_pie_host = tk.Frame(frame, bg=PALETTE["bg"])
        self._chart_pie_host.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)

        # Summary counter tiles
        tile_row = tk.Frame(frame, bg=PALETTE["bg"])
        tile_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=8, pady=4)

        tile_specs = [
            ("cnt_procs",    "⚙  Processes",    PALETTE["accent"]),
            ("cnt_svcs",     "🔧  Services",     PALETTE["teal"]),
            ("cnt_total",    "🚨  All Findings", PALETTE["yellow"]),
            ("cnt_critical", "🔴  Critical",      PALETTE["red"]),
            ("cnt_high",     "🟠  High",          PALETTE["orange"]),
        ]
        self._stat_tiles = {}
        for col_idx, (key, label_text, colour) in enumerate(tile_specs):
            tile = tk.Frame(tile_row, bg=PALETTE["panel"], padx=12, pady=8)
            tile.grid(row=0, column=col_idx, padx=6, pady=4, sticky="ew")
            tk.Label(
                tile, text=label_text,
                bg=PALETTE["panel"], fg=PALETTE["subtext"], font=FONT_BODY,
            ).pack()
            num_lbl = tk.Label(
                tile, text="0",
                bg=PALETTE["panel"], fg=colour,
                font=("Segoe UI", 18, "bold"),
            )
            num_lbl.pack()
            self._stat_tiles[key] = num_lbl

        tile_row.columnconfigure(tuple(range(len(tile_specs))), weight=1)
        return frame

    def _refresh_stats_view(self, data: dict) -> None:
        """Redraw counter tiles and regenerate embedded charts."""
        counts = alert_engine.tally_by_level()

        self._stat_tiles["cnt_procs"].config(text=str(len(data.get("processes", []))))
        self._stat_tiles["cnt_svcs"].config(text=str(len(data.get("services", []))))
        self._stat_tiles["cnt_total"].config(text=str(sum(counts.values())))
        self._stat_tiles["cnt_critical"].config(text=str(counts.get("CRITICAL", 0)))
        self._stat_tiles["cnt_high"].config(text=str(counts.get("HIGH", 0)))

        for widget in self._chart_bar_host.winfo_children():
            widget.destroy()
        for widget in self._chart_pie_host.winfo_children():
            widget.destroy()

        bar = build_bar_chart(self._chart_bar_host, counts)
        bar.get_tk_widget().pack(fill="both", expand=True)
        bar.draw()

        pie = build_pie_chart(self._chart_pie_host, counts)
        pie.get_tk_widget().pack(fill="both", expand=True)
        pie.draw()

    # ── Process map (graph) panel ──────────────────────────────────────────────

    def _init_graph_panel(self) -> ttk.Frame:
        frame = ttk.Frame(self._notebook)
        self._graph_host = tk.Frame(frame, bg=PALETTE["bg"])
        self._graph_host.pack(fill="both", expand=True, padx=8, pady=8)
        return frame

    def _refresh_proc_graph(self, processes: list) -> None:
        """Rebuild and redraw the process relationship graph."""
        for widget in self._graph_host.winfo_children():
            widget.destroy()
        graph_canvas = build_process_graph(self._graph_host, processes)
        graph_canvas.get_tk_widget().pack(fill="both", expand=True)
        graph_canvas.draw()

    # ── Reusable table builder ─────────────────────────────────────────────────

    def _create_data_table(
        self, parent, cols, headers, widths
    ) -> tuple:
        """
        Build a scrollable Treeview table inside *parent* and return
        (treeview, container_frame).

        Parameters
        ----------
        parent  : widget  — Parent frame.
        cols    : tuple   — Column identifier strings.
        headers : tuple   — Display header strings.
        widths  : tuple   — Initial column widths in pixels.
        """
        container = tk.Frame(parent, bg=PALETTE["bg"])
        container.pack(fill="both", expand=True, padx=6, pady=6)

        tv = ttk.Treeview(container, columns=cols, show="headings", selectmode="browse")
        for col, hdr, w in zip(cols, headers, widths):
            tv.heading(col, text=hdr)
            tv.column(col, width=w, minwidth=40, anchor="w")

        v_scroll = ttk.Scrollbar(container, orient="vertical",   command=tv.yview)
        h_scroll = ttk.Scrollbar(container, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        tv.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        return tv, container

    # ── Auto-refresh loop ──────────────────────────────────────────────────────

    def _launch_refresh_loop(self) -> None:
        """Start a daemon thread that periodically triggers a new scan."""
        def _loop():
            while True:
                if self._auto_refresh.get():
                    self.after(0, self._trigger_manual_scan)
                time.sleep(self._poll_interval)

        threading.Thread(target=_loop, daemon=True).start()

    def _trigger_manual_scan(self) -> None:
        """Kick off a fresh scan in a background thread and update the UI."""
        self._lbl_status.config(text="⟳  Running scan…")
        self.update_idletasks()

        def _run():
            try:
                self._trigger_scan()
                data = self._get_scan_data()
                self._latest_data = data
                self.after(0, lambda: self._apply_scan_results(data))
            except Exception as exc:
                self.after(
                    0,
                    lambda: self._lbl_status.config(text=f"Scan error: {exc}")
                )

        threading.Thread(target=_run, daemon=True).start()

    def _apply_scan_results(self, data: dict) -> None:
        """Push all scan results into the six tab panels."""
        self._refresh_process_rows(data.get("processes", []))
        self._refresh_service_rows(data.get("services", []))
        self._refresh_startup_rows(data.get("startup_entries", []))
        self._redraw_finding_rows()
        self._refresh_stats_view(data)
        self._refresh_proc_graph(data.get("processes", []))

        ts = datetime.now().strftime("%H:%M:%S")
        self._lbl_status.config(text=f"✅  Last scan completed at {ts}")
        self._lbl_scan_ts.config(text=f"Updated: {ts}")

    # ── Callbacks ──────────────────────────────────────────────────────────────

    def _handle_new_finding(self, finding: dict) -> None:
        """Reactive callback — refresh the findings tab on each new alert."""
        self.after(0, self._redraw_finding_rows)

    def _on_search_updated(self, *_) -> None:
        """Re-filter visible rows whenever the search field changes."""
        if self._latest_data:
            self._refresh_process_rows(self._latest_data.get("processes", []))
            self._refresh_service_rows(self._latest_data.get("services", []))

    # ── Report export ──────────────────────────────────────────────────────────

    def _save_report(self) -> None:
        """Export scan results to PDF, TXT, and JSON reports."""
        from utils.report_generator import export_all

        data = self._latest_data
        if not data:
            messagebox.showinfo("Export", "Please run at least one scan before exporting.")
            return

        data["alert_counts"] = alert_engine.tally_by_level()
        data["alerts"]       = alert_engine.fetch_all_findings()
        data["scan_time"]    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def _run_export():
            try:
                paths = export_all(data)
                summary = (
                    f"Reports saved to reports/\n\n"
                    f"  PDF  : {os.path.basename(paths['pdf'])}\n"
                    f"  TXT  : {os.path.basename(paths['txt'])}\n"
                    f"  JSON : {os.path.basename(paths['json'])}"
                )
                self.after(0, lambda: messagebox.showinfo("Export Complete", summary))
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Export Failed", str(exc)))

        threading.Thread(target=_run_export, daemon=True).start()
