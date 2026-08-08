"""Shared helpers for framework payload path conventions."""

from __future__ import annotations

NOPAYLOAD_PATHS = frozenset({"nopayload", "none"})

DOWNLOAD_STAGER_MARKERS = (
    "curl_python_stager",
    "wget_python_stager",
    "curl_pipe_bash_stager",
    "python_urllib_stager",
    "powershell_iex_stager",
    "certutil_exe_stager",
    "bitsadmin_exe_stager",
    "curl_exe_stager",
    "mshta_remote_stager",
    "regsvr32_sct_stager",
    "rundll32_js_stager",
    "wmic_xsl_stager",
    "msbuild_remote_stager",
    "python_thin_stager",
)


def is_nopayload_path(path: str) -> bool:
    """True when path selects built-in exploit delivery (no framework payload module)."""
    return str(path or "").strip().lower() in NOPAYLOAD_PATHS


def normalize_nopayload_path(path: str) -> str:
    """Return canonical nopayload token, or the stripped path unchanged."""
    text = str(path or "").strip().lower()
    if text in NOPAYLOAD_PATHS:
        return text
    return str(path or "").strip()


def is_download_stager_path(path: str) -> bool:
    """True for curl/wget/certutil/IEX second-stage delivery payloads."""
    low = str(path or "").lower()
    return any(m in low for m in DOWNLOAD_STAGER_MARKERS)


def requires_host_stager(path: str) -> bool:
    """True when exploit should auto-start host_stager before run."""
    return is_download_stager_path(path)
