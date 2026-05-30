"""
utils/virustotal.py
Project : ProWin — Windows Service & Process Monitoring Agent
"""

import requests
from utils.helpers import load_config, compute_file_hash

_CFG     = load_config()
_API_KEY = _CFG.get("virustotal_api_key", "").strip()

_VT_API_BASE = "https://www.virustotal.com/api/v3"
_VT_HEADERS  = {"x-apikey": _API_KEY}


def integration_active() -> bool:
    """
    Return True if a VirusTotal API key has been configured and the
    integration is therefore operational.
    """
    return bool(_API_KEY)


def _disabled_result(file_hash: str) -> dict:
    """Build a standardised 'not configured' result dict."""
    return {
        "hash":      file_hash,
        "score":     "N/A",
        "malicious": 0,
        "total":     0,
        "status":    "disabled",
        "permalink": "",
        "error":     "VirusTotal API key not set — add it to config/settings.json",
    }


def query_hash_reputation(file_hash: str) -> dict:
    """
    Submit a SHA-256 hash to VirusTotal and return a structured result dict.

    Parameters
    ----------
    file_hash : str
        64-character lowercase SHA-256 hex digest of the target file.

    Returns
    -------
    dict with keys:
        hash       — the queried digest
        score      — 'malicious_count/total_engines' string
        malicious  — integer count of engines flagging the file
        total      — total number of engines that analysed the file
        status     — one of 'clean', 'suspicious', 'malicious', 'unknown',
                     'disabled', or 'error'
        permalink  — direct VirusTotal GUI URL for manual review
        error      — error message string, or None on success
    """
    if not integration_active():
        return _disabled_result(file_hash)

    try:
        endpoint = f"{_VT_API_BASE}/files/{file_hash}"
        response = requests.get(endpoint, headers=_VT_HEADERS, timeout=10)

        if response.status_code == 404:
            # Hash not yet in VirusTotal database
            return {
                "hash":      file_hash,
                "score":     "0/0",
                "malicious": 0,
                "total":     0,
                "status":    "unknown",
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                "error":     None,
            }

        response.raise_for_status()
        payload    = response.json()
        stats      = payload["data"]["attributes"]["last_analysis_stats"]

        malicious_count  = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        engine_total     = sum(stats.values())
        score_str        = f"{malicious_count}/{engine_total}"

        if malicious_count > 0:
            verdict = "malicious"
        elif suspicious_count > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "hash":      file_hash,
            "score":     score_str,
            "malicious": malicious_count,
            "total":     engine_total,
            "status":    verdict,
            "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            "error":     None,
        }

    except requests.RequestException as exc:
        return {
            "hash":      file_hash,
            "score":     "N/A",
            "malicious": 0,
            "total":     0,
            "status":    "error",
            "permalink": "",
            "error":     str(exc),
        }


def scan_file_reputation(filepath: str) -> dict:
    """
    Compute the SHA-256 hash of a local file and query its VirusTotal
    reputation in one step.

    Parameters
    ----------
    filepath : str
        Absolute path to the file to check.

    Returns
    -------
    dict
        Same structure as query_hash_reputation(), with an additional
        'filepath' key populated.
    """
    digest = compute_file_hash(filepath)
    if not digest:
        return {
            "hash":      "",
            "score":     "N/A",
            "malicious": 0,
            "total":     0,
            "status":    "error",
            "permalink": "",
            "error":     f"File could not be read: {filepath}",
            "filepath":  filepath,
        }

    result             = query_hash_reputation(digest)
    result["filepath"] = filepath
    return result
