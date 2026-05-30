"""
gui/statistics.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import tkinter as tk
import matplotlib
matplotlib.use("Agg")   # Render-only backend — prevents standalone Tk windows
from matplotlib.figure import Figure
import matplotlib.patches as mpatches
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx

from gui.alerts import LEVEL_COLORS


# ── Chart colour tokens ───────────────────────────────────────────────────────
CHART_BG     = "#1e1e2e"   # chart area background
CHART_PANEL  = "#2a2a3e"   # axes / plot area background
CHART_FG     = "#cdd6f4"   # tick labels, titles, annotation text
CHART_ACCENT = "#89b4fa"   # accent line / focus element colour

# Severity colours in display order (CRITICAL → INFO)
_ORDERED_LEVELS  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_ORDERED_COLOURS = [LEVEL_COLORS[lv] for lv in _ORDERED_LEVELS]


# ── Bar chart ─────────────────────────────────────────────────────────────────

def build_bar_chart(host_frame: tk.Frame, level_counts: dict) -> FigureCanvasTkAgg:
    """
    Build a dark-themed vertical bar chart showing the distribution of
    security findings across severity levels and embed it in *host_frame*.

    Parameters
    ----------
    host_frame   : tk.Frame — Parent widget that will host the chart canvas.
    level_counts : dict     — {severity: count} mapping from tally_by_level().

    Returns
    -------
    FigureCanvasTkAgg
        Embedded canvas; call canvas.get_tk_widget().pack() to display it, then
        canvas.draw() to render the initial frame.
    """
    bar_values = [level_counts.get(lv, 0) for lv in _ORDERED_LEVELS]

    fig = Figure(figsize=(5, 3), dpi=96, facecolor=CHART_BG)
    ax  = fig.add_subplot(111)
    ax.set_facecolor(CHART_PANEL)

    bars = ax.bar(
        _ORDERED_LEVELS, bar_values,
        color=_ORDERED_COLOURS, edgecolor="#313244", linewidth=0.5
    )

    # Annotate each bar with its count value
    for bar, val in zip(bars, bar_values):
        if val > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                bar.get_height() + 0.1,
                str(val),
                ha="center", va="bottom",
                color=CHART_FG, fontsize=9, fontweight="bold",
            )

    ax.set_title("Finding Distribution by Severity", color=CHART_FG, fontsize=11, pad=8)
    ax.set_ylabel("Count", color=CHART_FG, fontsize=9)
    ax.tick_params(colors=CHART_FG, labelsize=8)
    ax.spines[:].set_color("#45475a")
    ax.yaxis.grid(True, color="#45475a", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)
    fig.tight_layout(pad=1.5)

    return FigureCanvasTkAgg(fig, master=host_frame)


# ── Pie chart ─────────────────────────────────────────────────────────────────

def build_pie_chart(host_frame: tk.Frame, level_counts: dict) -> FigureCanvasTkAgg:
    """
    Build a dark-themed proportional pie chart of security findings by
    severity and embed it in *host_frame*.

    Only non-zero severity levels appear as wedges; if no findings exist a
    centred placeholder message is rendered instead.

    Parameters
    ----------
    host_frame   : tk.Frame — Parent widget.
    level_counts : dict     — {severity: count} from tally_by_level().

    Returns
    -------
    FigureCanvasTkAgg
        Embedded chart canvas.
    """
    non_zero = [
        (lv, level_counts[lv], LEVEL_COLORS[lv])
        for lv in _ORDERED_LEVELS
        if level_counts.get(lv, 0) > 0
    ]

    fig = Figure(figsize=(4, 3), dpi=96, facecolor=CHART_BG)
    ax  = fig.add_subplot(111)
    ax.set_facecolor(CHART_BG)

    if non_zero:
        labels, values, colours = zip(*non_zero)
        _, label_texts, auto_texts = ax.pie(
            values,
            labels=labels,
            colors=colours,
            autopct="%1.0f%%",
            startangle=140,
            textprops={"color": CHART_FG, "fontsize": 8},
            wedgeprops={"edgecolor": CHART_BG, "linewidth": 1.5},
        )
        for at in auto_texts:
            at.set_fontsize(8)
            at.set_color(CHART_FG)
    else:
        ax.text(
            0.5, 0.5, "No Findings Yet",
            ha="center", va="center",
            color=CHART_FG, fontsize=11,
            transform=ax.transAxes,
        )

    ax.set_title("Findings Breakdown", color=CHART_FG, fontsize=10, pad=6)
    fig.tight_layout(pad=1.0)

    return FigureCanvasTkAgg(fig, master=host_frame)


# ── Process graph ─────────────────────────────────────────────────────────────

def build_process_graph(host_frame: tk.Frame, processes: list) -> FigureCanvasTkAgg:
    """
    Render an interactive process relationship graph using NetworkX spring
    layout, colour-coding each node by its assessed severity level, and embed
    it in *host_frame*.

    Only the first 60 processes are shown for readability.

    Parameters
    ----------
    host_frame : tk.Frame  — Parent widget.
    processes  : list[dict] — Process snapshots with pid, ppid, name, severity.

    Returns
    -------
    FigureCanvasTkAgg
        Embedded graph canvas.
    """
    fig = Figure(figsize=(7, 5), dpi=88, facecolor=CHART_BG)
    ax  = fig.add_subplot(111)
    ax.set_facecolor(CHART_BG)

    graph     = nx.DiGraph()
    displayed = processes[:60]
    pid_index = {p["pid"]: p for p in displayed}

    node_fill   = []
    node_labels = {}

    for proc in displayed:
        pid   = proc["pid"]
        label = f"{proc.get('name', '?')}\n{pid}"
        color = LEVEL_COLORS.get(proc.get("severity", "INFO"), "#6c757d")
        graph.add_node(pid)
        node_labels[pid] = label
        node_fill.append(color)

        ppid = proc.get("ppid", 0)
        if ppid in pid_index and ppid != pid:
            graph.add_edge(ppid, pid)

    if len(graph.nodes) == 0:
        ax.text(
            0.5, 0.5, "No process data available",
            ha="center", va="center",
            color=CHART_FG, fontsize=11,
            transform=ax.transAxes,
        )
    else:
        try:
            positions = nx.spring_layout(graph, seed=42, k=1.5)
        except Exception:
            positions = nx.random_layout(graph)

        nx.draw_networkx_nodes(
            graph, positions, ax=ax,
            node_color=node_fill, node_size=300, alpha=0.9
        )
        nx.draw_networkx_edges(
            graph, positions, ax=ax,
            edge_color="#585b70", arrows=True, arrowsize=10, alpha=0.6
        )
        nx.draw_networkx_labels(
            graph, positions, labels=node_labels, ax=ax,
            font_size=5, font_color=CHART_FG
        )

    ax.set_title("Process Relationship Map", color=CHART_FG, fontsize=10, pad=6)
    ax.axis("off")

    legend_entries = [
        mpatches.Patch(color=LEVEL_COLORS[lv], label=lv)
        for lv in _ORDERED_LEVELS
    ]
    ax.legend(
        handles=legend_entries, loc="lower right",
        facecolor=CHART_PANEL, labelcolor=CHART_FG,
        fontsize=7, framealpha=0.7
    )

    fig.tight_layout()
    return FigureCanvasTkAgg(fig, master=host_frame)
