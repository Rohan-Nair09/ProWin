"""
detection/whitelist.py
ProWin — Trusted-process registry.

Processes listed here are considered benign by default and will not produce
Unknown-process alerts. The lists are tuned for a typical Windows 10/11
workstation with common developer tooling installed.

Author  : Rohan Nair
Project : ProWin — Endpoint Monitoring Agent
"""

# ── Core Windows kernel and system processes ──────────────────────────────────
_WINDOWS_CORE: set = {
    "system", "system idle process", "idle", "registry",
    "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "lsass.exe", "lsm.exe",
    "services.exe", "svchost.exe", "spoolsv.exe", "dwm.exe",
    "taskhost.exe", "taskhostw.exe", "explorer.exe", "conhost.exe",
    "dllhost.exe", "msiexec.exe", "wuauclt.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "wmiprvse.exe", "wmiapsrv.exe", "audiodg.exe",
    "fontdrvhost.exe", "sihost.exe", "runtimebroker.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "ctfmon.exe", "consent.exe", "useroobe broker.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "msmpeng.exe", "nissrv.exe", "sgrmbroker.exe",
    "sppsvc.exe", "sppextcomobj.exe",
}

# ── Widely-used desktop applications ─────────────────────────────────────────
_COMMON_APPS: set = {
    "chrome.exe", "firefox.exe", "msedge.exe",
    "code.exe", "notepad.exe", "notepad++.exe",
    "python.exe", "pythonw.exe",
    "onedrive.exe", "teams.exe", "slack.exe",
    "discord.exe", "zoom.exe",
    "taskmgr.exe", "mmc.exe", "regedit.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe",
}

# ── Developer and IDE tooling ─────────────────────────────────────────────────
_DEV_TOOLS: set = {
    "devenv.exe", "idea64.exe", "pycharm64.exe",
    "git.exe", "node.exe",
}

# ── Security software agents ──────────────────────────────────────────────────
_SECURITY_AGENTS: set = {
    "mbam.exe", "avp.exe", "avgnt.exe",
}

# Unified trusted-process set
TRUSTED_PROCS: set = (
    _WINDOWS_CORE | _COMMON_APPS | _DEV_TOOLS | _SECURITY_AGENTS
)

# ── Multi-instance allowance ──────────────────────────────────────────────────
# These processes intentionally run as multiple simultaneous copies on a
# healthy Windows installation and must not be treated as hollowing suspects.
MULTI_COPY_ALLOWED: set = {
    "csrss.exe",            # one instance per Windows session
    "svchost.exe",          # dozens of instances are normal
    "conhost.exe",          # one per console window
    "dllhost.exe",          # COM surrogate — many copies expected
    "runtimebroker.exe",    # one per UWP app
    "backgroundtaskhost.exe",
    "wmiprvse.exe",
}

# ── CPU-alert exclusions ──────────────────────────────────────────────────────
# Kernel artefacts that show misleading CPU percentages and should never
# generate high-CPU alerts.
CPU_IGNORE_LIST: set = {
    "system idle process", "idle",
    "system", "registry",
    "memory compression",
}


# ── Lookup helpers ────────────────────────────────────────────────────────────

_TRUSTED_LOWER        = {p.lower() for p in TRUSTED_PROCS}
_MULTI_COPY_LOWER     = {p.lower() for p in MULTI_COPY_ALLOWED}
_CPU_IGNORE_LOWER     = {p.lower() for p in CPU_IGNORE_LIST}


def is_trusted(process_name: str) -> bool:
    """
    Return True if *process_name* belongs to the trusted-process registry.

    Parameters
    ----------
    process_name : str
        Executable name to check (case-insensitive).
    """
    return process_name.lower() in _TRUSTED_LOWER


def allows_multi_copy(process_name: str) -> bool:
    """
    Return True if running multiple simultaneous instances of *process_name*
    is considered normal on Windows and should not raise a duplication alert.
    """
    return process_name.lower() in _MULTI_COPY_LOWER


def skip_cpu_check(process_name: str) -> bool:
    """
    Return True if *process_name* should be exempt from high-CPU alerting
    (typically kernel idle or memory-management processes).
    """
    return process_name.lower() in _CPU_IGNORE_LOWER
