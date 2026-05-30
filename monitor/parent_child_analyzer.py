"""
monitor/parent_child_analyzer.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

from detection.rules_engine import check_spawn_chain


def construct_proc_hierarchy(processes: list) -> dict:
    """
    Build a nested process hierarchy from a flat list of process snapshots.

    Each entry in the returned dict maps a PID to a node containing the
    process record and a list of direct child PIDs.

    Parameters
    ----------
    processes : list[dict]
        Process records as returned by collect_running_processes().

    Returns
    -------
    dict
        {pid: {"proc": dict, "children": [child_pid, ...]}, ...}
    """
    hierarchy = {}
    pid_map   = {p["pid"]: p for p in processes}

    for proc in processes:
        pid  = proc["pid"]
        ppid = proc["ppid"]

        if pid not in hierarchy:
            hierarchy[pid] = {"proc": proc, "children": []}

        if ppid in pid_map and ppid != pid:
            if ppid not in hierarchy:
                hierarchy[ppid] = {"proc": pid_map[ppid], "children": []}
            if pid not in hierarchy[ppid]["children"]:
                hierarchy[ppid]["children"].append(pid)

    return hierarchy


def find_anomalous_spawn_chains(processes: list) -> list:
    """
    Evaluate every parent→child pair in the process list against the
    spawn-chain rule table and collect all matched findings.

    Parameters
    ----------
    processes : list[dict]
        Full process snapshot list.

    Returns
    -------
    list[dict]
        Finding dicts for each suspicious spawn relationship detected.
    """
    findings = []
    pid_map  = {p["pid"]: p for p in processes}

    for proc in processes:
        ppid        = proc.get("ppid", 0)
        parent_proc = pid_map.get(ppid)
        if not parent_proc:
            continue
        parent_name   = parent_proc.get("name", "")
        chain_findings = check_spawn_chain(parent_name, proc)
        findings.extend(chain_findings)

    return findings


def format_subtree(hierarchy: dict, root_pid: int, depth: int = 0) -> list:
    """
    Recursively render the subtree rooted at *root_pid* as indented text lines
    suitable for console or plain-text report output.

    Parameters
    ----------
    hierarchy : dict   — Output of construct_proc_hierarchy().
    root_pid  : int    — PID of the subtree root node.
    depth     : int    — Current indentation depth (0 = root level).

    Returns
    -------
    list[str]
        Indented text lines representing the subtree.
    """
    lines = []
    if root_pid not in hierarchy:
        return lines

    node   = hierarchy[root_pid]
    proc   = node["proc"]
    indent = "    " * depth
    branch = "└── " if depth > 0 else ""
    lines.append(f"{indent}{branch}{proc.get('name', '?')}  [PID:{proc.get('pid', '?')}]")

    for child_pid in node.get("children", []):
        lines.extend(format_subtree(hierarchy, child_pid, depth + 1))

    return lines


def render_full_forest(processes: list) -> str:
    """
    Render the complete process forest (all root-level trees) as a single
    printable string for use in text-based reports.

    Parameters
    ----------
    processes : list[dict]
        Full process snapshot list.

    Returns
    -------
    str
        Multi-line string representation of the entire process hierarchy.
    """
    hierarchy = construct_proc_hierarchy(processes)
    pid_map   = {p["pid"]: p for p in processes}
    all_pids  = set(pid_map.keys())

    # Root nodes are those whose parent PID is not in the collected set
    root_pids = [
        p["pid"] for p in processes
        if p["ppid"] not in all_pids or p["ppid"] == p["pid"]
    ]

    lines = []
    for root in sorted(root_pids):
        lines.extend(format_subtree(hierarchy, root))

    return "\n".join(lines)
