#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Low-level Paramiko transport helpers (unauthenticated probes, rekey, channels)."""

from __future__ import annotations

import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import paramiko
except ImportError:
    paramiko = None  # type: ignore

_ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|.)")
_ROUTEROS_PROMPT = b"] > "


def paramiko_available() -> bool:
    return paramiko is not None


def connect_transport(
    host: str,
    port: int = 22,
    timeout: float = 10.0,
    allow_ssh_rsa: bool = True,
) -> Tuple[Optional[Any], str]:
    """
    Start an SSH transport without authenticating.
    Returns (transport, error_message).
    """
    if paramiko is None:
        return None, "paramiko_required"
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        transport = paramiko.Transport(sock)
        if allow_ssh_rsa:
            transport.get_security_options().key_types += ("ssh-rsa",)
        transport.start_client(timeout=timeout)
        return transport, ""
    except Exception as exc:
        return None, str(exc)[:200]


def client_rekey(transport, timeout: float = 15.0) -> bool:
    """Trigger client-side KEX re-init and wait for completion."""
    if transport is None:
        return False
    transport._send_kex_init()
    deadline = time.monotonic() + timeout
    saw = False
    while time.monotonic() < deadline:
        in_kex = getattr(transport, "in_kex", False)
        if saw and not in_kex:
            return True
        if in_kex:
            saw = True
        if not getattr(transport, "active", False):
            return False
        time.sleep(0.1)
    return False


def try_open_session(transport, timeout: float = 8.0) -> Tuple[Optional[Any], str]:
    if transport is None:
        return None, "no_transport"
    try:
        return transport.open_session(timeout=timeout), ""
    except Exception as exc:
        return None, repr(exc)


def close_transport(transport) -> None:
    if transport is None:
        return
    try:
        transport.close()
    except Exception:
        pass


def probe_session_after_rekey(
    host: str,
    port: int = 22,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """
    MikroTik-style check: session channel refused before rekey, accepted after.
    """
    result: Dict[str, Any] = {
        "detected": False,
        "vulnerable": False,
        "banner": "",
        "control_open": False,
        "rekey_ok": False,
        "post_rekey_open": False,
        "error": "",
    }
    if paramiko is None:
        banner = _banner_only(host, port, timeout)
        result["banner"] = banner
        result["detected"] = bool(banner)
        result["error"] = "paramiko_required"
        return result

    transport, err = connect_transport(host, port, timeout)
    if not transport:
        result["error"] = err or "connect_failed"
        return result

    result["detected"] = True
    result["banner"] = str(getattr(transport, "remote_version", "") or "")
    control, _ = try_open_session(transport)
    result["control_open"] = control is not None
    if control:
        control.close()
    close_transport(transport)

    transport, err = connect_transport(host, port, timeout)
    if not transport:
        result["error"] = err or "reconnect_failed"
        return result

    result["rekey_ok"] = client_rekey(transport)
    test, _ = try_open_session(transport)
    result["post_rekey_open"] = test is not None
    if test:
        test.close()
    close_transport(transport)

    result["vulnerable"] = bool(
        result["rekey_ok"] and result["post_rekey_open"] and not result["control_open"]
    )
    return result


def run_routeros_shell_commands(
    host: str,
    port: int = 22,
    commands: Optional[List[str]] = None,
    timeout: float = 10.0,
    prompt_wait: float = 25.0,
    command_wait: float = 4.0,
) -> Dict[str, Any]:
    """
    Open interactive RouterOS shell after rekey and run commands.
    Returns {ok, outputs: [{command, output}], error}.
    """
    out: Dict[str, Any] = {"ok": False, "outputs": [], "error": ""}
    if paramiko is None:
        out["error"] = "paramiko_required"
        return out

    transport, err = connect_transport(host, port, timeout)
    if not transport or not client_rekey(transport):
        out["error"] = err or "rekey_failed"
        close_transport(transport)
        return out

    channel, err_ch = try_open_session(transport)
    if not channel:
        out["error"] = err_ch or "session_refused"
        close_transport(transport)
        return out

    channel.settimeout(2)
    channel.get_pty(term="vt100", width=100, height=30)
    channel.invoke_shell()
    buf = bytearray()
    deadline = time.monotonic() + prompt_wait
    while time.monotonic() < deadline and not channel.closed:
        if channel.recv_ready():
            buf.extend(channel.recv(4096))
        if _ROUTEROS_PROMPT in _ANSI.sub(b"", bytes(buf)):
            break
        time.sleep(0.2)

    cmd_list = [c.strip() for c in (commands or []) if c and c.strip()]
    if not cmd_list:
        cmd_list = [":put [/system resource get version]"]

    for cmd in cmd_list:
        mark = len(buf)
        channel.sendall(cmd.encode() + b"\r")
        time.sleep(command_wait)
        while channel.recv_ready():
            buf.extend(channel.recv(4096))
        chunk = _ANSI.sub(b"", bytes(buf[mark:])).replace(b"\r", b"")
        text = chunk.decode(errors="replace").strip()
        out["outputs"].append({"command": cmd, "output": text})

    close_transport(transport)
    out["ok"] = True
    return out


def _banner_only(host: str, port: int, timeout: float) -> str:
    from lib.scanner.ssh.detectors import probe_ssh_banner

    info = probe_ssh_banner(host, int(port), timeout)
    return str(info.get("banner") or "")
