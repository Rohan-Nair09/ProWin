"""
detection/blacklist.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

# ── Threat Catalogue ──────────────────────────────────────────────────────────
#
# Entries use lowercase names. The lookup function normalises on the fly so
# mixed-case executables are still matched correctly.

# Credential-dumping and red-team frameworks
_CREDENTIAL_DUMPERS: set = {
    "mimikatz.exe", "pwdump.exe", "fgdump.exe",
    "wce.exe", "gsecdump.exe", "lsadump.exe",
    "procdump.exe",
}

# Remote-access trojans and post-exploitation agents
_REMOTE_ACCESS_TOOLS: set = {
    "meterpreter.exe", "msfconsole.exe",
    "cobaltstrike.exe", "beacon.exe",
    "njrat.exe", "darkcomet.exe", "quasar.exe",
    "asyncrat.exe", "xtremerat.exe", "poisonivy.exe",
    "nanocore.exe", "remcos.exe", "luminosity.exe",
}

# Ransomware families whose processes have been documented in the wild
_RANSOMWARE_PROCS: set = {
    "wannacry.exe", "notpetya.exe", "ryuk.exe", "locky.exe",
}

# Script-based attack frameworks and spray tools
_ATTACK_FRAMEWORKS: set = {
    "powersploit.exe", "empire.exe", "pspray.exe",
    "havoc.exe", "sliver.exe",
}

# Process names crafted to impersonate legitimate Windows executables
_IMPERSONATORS: set = {
    "svch0st.exe", "scvhost.exe",
    "lssas.exe", "cssrs.exe",
    "crss.exe", "winlogon32.exe",
    "iexplore32.exe",
}

# Cryptocurrency mining software
_CRYPTO_MINERS: set = {
    "xmrig.exe", "minerd.exe",
    "cgminer.exe", "bfgminer.exe",
}

# Network reconnaissance and exploitation utilities
_NETWORK_RECON: set = {
    "nmap.exe", "masscan.exe", "zmap.exe",
    "sqlmap.exe",
}

# Unified threat set — union of all categories above
KNOWN_THREATS: set = (
    _CREDENTIAL_DUMPERS
    | _REMOTE_ACCESS_TOOLS
    | _RANSOMWARE_PROCS
    | _ATTACK_FRAMEWORKS
    | _IMPERSONATORS
    | _CRYPTO_MINERS
    | _NETWORK_RECON
)


# ── Lookup ────────────────────────────────────────────────────────────────────

_KNOWN_THREATS_LOWER: set = {name.lower() for name in KNOWN_THREATS}


def is_known_threat(process_name: str) -> bool:
    """
    Check whether *process_name* appears in the known-threat catalogue.

    Parameters
    ----------
    process_name : str
        Executable filename to check (case-insensitive).

    Returns
    -------
    bool
        True if the process matches a catalogued threat, False otherwise.
    """
    return process_name.lower() in _KNOWN_THREATS_LOWER
