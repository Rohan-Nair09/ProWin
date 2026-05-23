"""
utils/signature_checker.py
SentinelEye — Windows Authenticode signature verification module.

Calls the WinVerifyTrust API via ctypes to determine whether an executable
carries a valid Authenticode digital signature. Falls back to a win32api
version-info probe if the primary method is unavailable.

Author  : Rohan Nair
Project : SentinelEye — Endpoint Monitoring Agent
"""

import ctypes
import ctypes.wintypes
import os

# GUID string for the generic Authenticode verification action
_AUTHENTICODE_ACTION = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"

# WinVerifyTrust return code for a valid signature
_TRUST_E_OK = 0


# ── WinTrust C structures (ctypes mapping) ────────────────────────────────────

class _WinTrustFileInfo(ctypes.Structure):
    """Mirrors the WINTRUST_FILE_INFO Win32 structure."""
    _fields_ = [
        ("cbStruct",         ctypes.c_ulong),
        ("pcwszFilePath",    ctypes.c_wchar_p),
        ("hFile",            ctypes.wintypes.HANDLE),
        ("pgKnownSubject",   ctypes.c_void_p),
    ]


class _WinTrustData(ctypes.Structure):
    """Mirrors the WINTRUST_DATA Win32 structure."""
    _fields_ = [
        ("cbStruct",               ctypes.c_ulong),
        ("pPolicyCallbackData",    ctypes.c_void_p),
        ("pSIPClientData",         ctypes.c_void_p),
        ("dwUIChoice",             ctypes.c_ulong),   # 2 = WTD_UI_NONE
        ("fdwRevocationChecks",    ctypes.c_ulong),   # 0 = WTD_REVOKE_NONE
        ("dwUnionChoice",          ctypes.c_ulong),   # 1 = WTD_CHOICE_FILE
        ("pFile",                  ctypes.POINTER(_WinTrustFileInfo)),
        ("dwStateAction",          ctypes.c_ulong),
        ("hWVTStateData",          ctypes.wintypes.HANDLE),
        ("pwszURLReference",       ctypes.c_wchar_p),
        ("dwProvFlags",            ctypes.c_ulong),
        ("dwUIContext",            ctypes.c_ulong),
    ]


# ── Primary verification ──────────────────────────────────────────────────────

def verify_executable_signature(filepath: str) -> str:
    """
    Determine the Authenticode signature status of a Windows executable by
    invoking WinVerifyTrust from wintrust.dll.

    Parameters
    ----------
    filepath : str
        Absolute path to the PE file to examine.

    Returns
    -------
    str
        One of:
          'SIGNED'   — valid Authenticode chain found.
          'UNSIGNED' — file exists but carries no valid signature.
          'UNKNOWN'  — file unreadable or verification infrastructure failed.
    """
    if not filepath or not os.path.isfile(filepath):
        return "UNKNOWN"

    try:
        wintrust_dll = ctypes.WinDLL("wintrust")

        file_struct               = _WinTrustFileInfo()
        file_struct.cbStruct      = ctypes.sizeof(_WinTrustFileInfo)
        file_struct.pcwszFilePath = filepath
        file_struct.hFile         = None
        file_struct.pgKnownSubject = None

        trust_struct                       = _WinTrustData()
        trust_struct.cbStruct              = ctypes.sizeof(_WinTrustData)
        trust_struct.pPolicyCallbackData   = None
        trust_struct.pSIPClientData        = None
        trust_struct.dwUIChoice            = 2       # WTD_UI_NONE
        trust_struct.fdwRevocationChecks   = 0       # WTD_REVOKE_NONE
        trust_struct.dwUnionChoice         = 1       # WTD_CHOICE_FILE
        trust_struct.pFile                 = ctypes.pointer(file_struct)
        trust_struct.dwStateAction         = 0
        trust_struct.hWVTStateData         = None
        trust_struct.pwszURLReference      = None
        trust_struct.dwProvFlags           = 0x00000010  # cache-only URL retrieval
        trust_struct.dwUIContext            = 0

        import comtypes
        action_guid = comtypes.GUID(_AUTHENTICODE_ACTION)

        rc = wintrust_dll.WinVerifyTrust(
            ctypes.wintypes.HANDLE(-1),   # INVALID_HANDLE_VALUE → no UI parent
            ctypes.byref(action_guid),
            ctypes.byref(trust_struct),
        )
        return "SIGNED" if rc == _TRUST_E_OK else "UNSIGNED"

    except Exception:
        return _fallback_version_check(filepath)


def _fallback_version_check(filepath: str) -> str:
    """
    Secondary check using win32api's GetFileVersionInfo when the primary
    WinVerifyTrust path is unavailable (e.g. comtypes not installed).

    Parameters
    ----------
    filepath : str
        Absolute path to the target executable.

    Returns
    -------
    str
        'SIGNED', 'UNSIGNED', or 'UNKNOWN'.
    """
    try:
        import win32api
        version_info = win32api.GetFileVersionInfo(filepath, "\\")
        return "SIGNED" if version_info else "UNSIGNED"
    except Exception:
        return "UNKNOWN"
