#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic helpers for Linux shell / SSH / Meterpreter post modules."""

from __future__ import annotations

import base64
import os
import re
import shlex
from typing import Optional

from core.framework.enums import SessionType
from core.output_handler import print_error, print_status, print_warning
from core.framework.shell.root_elevate import is_root_uid_output

KS_FILE_MARKER = "__KS_FILE__:"


class LinuxSessionMixin:
    """Mixin for Post modules — expects cmd_execute/cmd_exec, session_id, framework."""

    def _linux_sid(self) -> str:
        return str(getattr(self, "session_id", "") or "").strip()

    def _linux_session_type(self) -> str:
        sid = self._linux_sid()
        if not sid or not getattr(self, "framework", None):
            return ""
        sm = getattr(self.framework, "session_manager", None)
        if not sm:
            return ""
        session = sm.get_session(sid)
        if not session:
            return ""
        return (getattr(session, "session_type", "") or "").lower()

    def _linux_meterpreter(self) -> bool:
        return self._linux_session_type() == SessionType.METERPRETER.value.lower()

    def linux_execute(self, command: str, *, timeout: int = 0, pty: bool = False) -> str:
        if not command:
            return ""
        if self._linux_meterpreter() and not command.lstrip().lower().startswith("shell "):
            command = f"shell {command}"
        try:
            kwargs: dict = {}
            if timeout > 0:
                kwargs["timeout"] = timeout
            if hasattr(self, "cmd_execute"):
                try:
                    output = self.cmd_execute(command, pty=pty, **kwargs)
                except TypeError:
                    output = self.cmd_execute(command, **kwargs)
            else:
                output = self.cmd_exec(command)
            return (output or "").strip()
        except TypeError:
            output = self.cmd_exec(command) if hasattr(self, "cmd_exec") else self.cmd_execute(command)
            return (output or "").strip()
        except Exception as exc:
            print_warning(f"Command failed: {exc}")
            return ""

    @staticmethod
    def linux_shell_quote(value: str) -> str:
        return shlex.quote(str(value))

    def linux_require_linux(self) -> bool:
        if not self._linux_sid():
            print_error("Session ID is required.")
            return False
        out = self.linux_execute("uname -s 2>/dev/null || echo UNKNOWN")
        if not out or "linux" not in out.lower():
            if any(token in out.lower() for token in ("connection lost", "no response", "disconnected")):
                print_error("Session disconnected — reconnect the payload before running post modules.")
            else:
                print_error("Linux session required.")
            return False
        return True

    def linux_is_root(self) -> bool:
        out = self.linux_execute("id -u 2>/dev/null")
        return is_root_uid_output(out)

    def linux_command_exists(self, cmd: str) -> bool:
        if hasattr(self, "command_exists"):
            return bool(self.command_exists(cmd))
        out = self.linux_execute(f"command -v {shlex.quote(cmd)} >/dev/null 2>&1 && echo OK")
        return "OK" in out

    def linux_remote_file_size(self, path: str) -> int:
        q = self.linux_shell_quote(path)
        out = self.linux_execute(f"stat -c%s {q} 2>/dev/null || wc -c < {q} 2>/dev/null")
        if not out:
            return 0
        tail = out.splitlines()[-1].strip()
        try:
            return int(tail)
        except ValueError:
            digits = re.sub(r"\D", "", tail)
            return int(digits) if digits else 0

    def linux_file_exists(self, path: str) -> bool:
        q = self.linux_shell_quote(path)
        out = self.linux_execute(f"test -f {q} && echo OK || echo MISSING")
        return "OK" in out

    def linux_read_remote_chunk_b64(self, path: str, offset: int, length: int) -> bytes:
        q = self.linux_shell_quote(path)
        cmd = (
            f"dd if={q} bs=1 skip={int(offset)} count={int(length)} 2>/dev/null "
            f"| base64 | tr -d '\\n'"
        )
        out = self.linux_execute(cmd, timeout=60)
        clean = re.sub(r"\s+", "", out)
        if not clean:
            return b""
        return base64.b64decode(clean)

    def linux_pull_file_via_session(
        self,
        remote_path: str,
        local_path: str,
        *,
        chunk_kb: int = 512,
    ) -> bool:
        size = self.linux_remote_file_size(remote_path)
        if size <= 0:
            print_error(f"Remote file is missing or empty: {remote_path}")
            return False

        print_status(f"Downloading {size} bytes...")
        chunk = max(1024, int(chunk_kb) * 1024)
        parts = []
        offset = 0
        while offset < size:
            n = min(chunk, size - offset)
            blob = self.linux_read_remote_chunk_b64(remote_path, offset, n)
            if len(blob) != n:
                print_error(f"Chunk read mismatch at offset {offset}.")
                return False
            parts.append(blob)
            offset += n
            if size > chunk:
                pct = int((offset * 100) / size)
                print_status(f"Download progress: {pct}%")

        parent = os.path.dirname(os.path.abspath(local_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(local_path, "wb") as handle:
            handle.write(b"".join(parts))
        return True

    def linux_write_remote_b64_text(
        self,
        b64_payload: str,
        remote_path: str,
        *,
        chunk_size: int = 4096,
    ) -> None:
        q = self.linux_shell_quote(remote_path)
        self.linux_execute(f": > {q}")
        for i in range(0, len(b64_payload), chunk_size):
            chunk = b64_payload[i:i + chunk_size]
            cq = self.linux_shell_quote(chunk)
            self.linux_execute(f"printf '%s' {cq} >> {q}")

    def linux_upload_bytes(
        self,
        data: bytes,
        remote_path: str,
        *,
        executable: bool = False,
        chunk_size: int = 4096,
        pty: bool = False,
    ) -> bool:
        if not data:
            print_error("Empty payload — nothing to upload.")
            return False

        q_remote = self.linux_shell_quote(remote_path)
        self.linux_execute(f"rm -f {q_remote}", pty=pty)

        if self.linux_command_exists("base64"):
            encoded = base64.b64encode(data).decode("ascii")
            b64_path = f"{remote_path}.b64"
            self.linux_write_remote_b64_text(encoded, b64_path, chunk_size=chunk_size)
            q_b64 = self.linux_shell_quote(b64_path)
            self.linux_execute(f"base64 -d {q_b64} > {q_remote}", pty=pty)
            self.linux_execute(f"rm -f {q_b64}", pty=pty)
        else:
            print_warning("base64 not found on target, falling back to hex upload...")
            hex_data = data.hex()
            hex_chunk = 1024
            for i in range(0, len(hex_data), hex_chunk):
                chunk = hex_data[i:i + hex_chunk]
                hex_formatted = "".join(f"\\x{chunk[j:j + 2]}" for j in range(0, len(chunk), 2))
                cq = self.linux_shell_quote(hex_formatted)
                self.linux_execute(f"printf {cq} >> {q_remote}", pty=pty)

        if executable:
            self.linux_execute(f"chmod +x {q_remote}", pty=pty)

        expected = len(data)
        check = self.linux_execute(
            f"test -s {q_remote} "
            f"&& [ \"$(wc -c < {q_remote} 2>/dev/null)\" = {expected} ] "
            "&& echo OK || echo FAIL",
            pty=pty,
        )
        if check != "OK":
            print_error(f"Upload verification failed for {remote_path}.")
            return False
        return True

    def linux_upload_file(
        self,
        local_path: str,
        remote_path: str,
        *,
        chunk_size: int = 4096,
    ) -> bool:
        if not os.path.isfile(local_path):
            print_error(f"Local file not found: {local_path}")
            return False
        with open(local_path, "rb") as handle:
            data = handle.read()
        print_status(f"Uploading {len(data)} bytes to {remote_path}...")
        b64_path = f"{remote_path}.b64"
        self.linux_write_remote_b64_text(
            base64.b64encode(data).decode("ascii"),
            b64_path,
            chunk_size=chunk_size,
        )
        q_remote = self.linux_shell_quote(remote_path)
        q_b64 = self.linux_shell_quote(b64_path)
        if self.linux_command_exists("base64"):
            self.linux_execute(f"base64 -d {q_b64} > {q_remote}")
        else:
            self.linux_execute(f"openssl base64 -d -in {q_b64} -out {q_remote}")
        self.linux_execute(f"rm -f {q_b64}")
        return self.linux_remote_file_size(remote_path) == len(data)

    def linux_delete_remote(self, paths) -> None:
        for path in paths:
            if path:
                self.linux_execute(f"rm -f {self.linux_shell_quote(path)}")

    @staticmethod
    def linux_int_opt(val, default: int, minimum: Optional[int] = None) -> int:
        try:
            n = int(val)
        except Exception:
            n = default
        if minimum is not None and n < minimum:
            n = minimum
        return n
