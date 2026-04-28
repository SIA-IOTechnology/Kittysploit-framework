#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64
import re

class Module(Post):
    _DEFAULT_BUFFER_LEN = 65536
    _DEFAULT_FORCE = True
    _AUTO_CLEANUP = True

    __info__ = {
        "name": "Windows Find AV Signature",
        "description": (
            "Locate tiny AV signatures by generating progressive binary splits on a Windows "
            "shell or Meterpreter session."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "http://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html",
            "https://github.com/mattifestation/PowerSploit",
        ],
    }

    target_path = OptString("", "Target binary path on remote host", True)
    interval = OptInteger(10000, "Split interval size", False)
    start_byte = OptInteger(0, "First byte index to begin splitting", False)
    end_byte = OptString("max", "Last byte index or 'max'", False)

    def _powershell_script(self) -> str:
        return r"""
function Find-AVSignature
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateRange(0,4294967295)]
        [UInt32]
        $StartByte,

        [Parameter(Mandatory = $True)]
        [String]
        $EndByte,

        [Parameter(Mandatory = $True)]
        [ValidateRange(1,4294967295)]
        [UInt32]
        $Interval,

        [Parameter(Mandatory = $True)]
        [String]
        [ValidateScript({Test-Path $_ })]
        $Path,

        [String]
        $OutPath = "",

        [ValidateRange(1,2097152)]
        [UInt32]
        $BufferLen = 65536,

        [Switch] $Force
    )

    if (!(Test-Path $Path)) { throw "File path not found" }
    if (!(Get-ChildItem -LiteralPath $Path).Exists) { throw "File not found" }

    if ([String]::IsNullOrWhiteSpace($OutPath)) {
        $OutPath = Split-Path -LiteralPath $Path -Parent
    }

    $Response = $True
    if (!(Test-Path $OutPath)) {
        if ($Force -or ($Response = $psCmdlet.ShouldContinue("The `"$OutPath`" does not exist! Do you want to create the directory?",""))) {
            New-Item -Path $OutPath -ItemType Directory | Out-Null
        }
    }
    if (!$Response) { throw "Output path not found" }

    [Int64]$FileSize = (Get-ChildItem -LiteralPath $Path).Length
    if ($FileSize -le 0) { throw "Input file is empty" }

    if ($StartByte -gt ($FileSize - 1)) { throw "StartByte range must be between 0 and $($FileSize - 1)" }
    [Int64] $MaximumByte = $FileSize - 1

    if ($EndByte -ceq "max") { $EndByte = $MaximumByte }
    [Int64]$EndByte = [Int64]$EndByte

    if ($EndByte -gt $MaximumByte) { $EndByte = $MaximumByte }
    if ($EndByte -lt $StartByte) { $EndByte = [Int64]$StartByte + [Int64]$Interval }
    if ($EndByte -gt $MaximumByte) { $EndByte = $MaximumByte }

    Write-Verbose "StartByte: $StartByte"
    Write-Verbose "EndByte: $EndByte"

    [String] $FileName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    [Int64] $ResultNumber = [Math]::Floor(($EndByte - $StartByte) / $Interval)
    if ((($EndByte - $StartByte) % $Interval) -gt 0) { $ResultNumber = $ResultNumber + 1 }

    $Response = $True
    if ($Force -or ($Response = $psCmdlet.ShouldContinue("This script will result in $ResultNumber binaries being written to `"$OutPath`"!",
             "Do you want to continue?"))) { }
    if (!$Response) { return }

    Write-Verbose "This script will now write $ResultNumber binaries to `"$OutPath`"."
    [Byte[]] $ReadBuffer = New-Object byte[] $BufferLen
    [System.IO.FileStream] $ReadStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, $BufferLen)

    try {
        for ([Int64]$i = 0; $i -le $ResultNumber; $i++) {
            if ($i -eq $ResultNumber) { [Int64]$SplitByte = $EndByte }
            else { [Int64]$SplitByte = [Int64]$StartByte + ([Int64]$Interval * $i) }

            Write-Verbose "Byte 0 -> $($SplitByte)"
            $ReadStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

            [String] $OutFile = Join-Path $OutPath "$($FileName)_$($SplitByte).bin"
            [System.IO.FileStream] $WriteStream = New-Object System.IO.FileStream($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, $BufferLen)

            try {
                [Int64] $BytesLeft = $SplitByte
                while ($BytesLeft -gt $BufferLen) {
                    [Int32]$Count = $ReadStream.Read($ReadBuffer, 0, $BufferLen)
                    if ($Count -le 0) { break }
                    $WriteStream.Write($ReadBuffer, 0, $Count)
                    $BytesLeft = $BytesLeft - $Count
                }

                while ($BytesLeft -gt 0) {
                    [Int32]$ReadSize = [Math]::Min($BufferLen, [Int32]$BytesLeft)
                    [Int32]$Count = $ReadStream.Read($ReadBuffer, 0, $ReadSize)
                    if ($Count -le 0) { break }
                    $WriteStream.Write($ReadBuffer, 0, $Count)
                    $BytesLeft = $BytesLeft - $Count
                }
            }
            finally {
                $WriteStream.Close()
                $WriteStream.Dispose()
            }
        }
    }
    finally {
        $ReadStream.Dispose()
    }

    [System.GC]::Collect()
    Write-Verbose "Completed!"
}
"""

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
        output = self._execute_cmd("echo %TEMP%")
        if output:
            return output.splitlines()[0].strip().rstrip("\\")
        return "C:\\Windows\\Temp"

    def _ps_single_quote(self, value: str) -> str:
        return str(value).replace("'", "''")

    def _write_remote_script(self, temp_dir: str):
        script_path = f"{temp_dir}\\find_av_signature.ps1"
        blob_path = f"{temp_dir}\\find_av_signature.b64"
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

    def _validate_options(self):
        if self.start_byte < 0:
            raise ProcedureError(FailureType.ConfigurationError, "start_byte must be >= 0")
        if self.interval <= 0:
            raise ProcedureError(FailureType.ConfigurationError, "interval must be > 0")
        if not str(self.target_path or "").strip():
            raise ProcedureError(FailureType.ConfigurationError, "target_path is required")

    def _cleanup_remote(self, paths):
        for path in paths:
            self._execute_cmd(f'del /f /q "{path}"')

    def check(self):
        ps_check = self._execute_cmd('powershell -NoP -Command "Write-Output 1"')
        if "1" not in ps_check:
            print_error("PowerShell is not available on the target")
            return False
        return True

    def run(self):
        self._validate_options()

        temp_dir = self._remote_temp_dir()
        print_status("Uploading Find-AVSignature payload...")
        script_path, blob_path = self._write_remote_script(temp_dir)

        end_value = str(self.end_byte).strip() if str(self.end_byte).strip() else "max"
        remote_target = self._ps_single_quote(str(self.target_path).strip())
        remote_end = self._ps_single_quote(end_value)

        invoke = (
            "$ErrorActionPreference='Stop';"
            f". '{self._ps_single_quote(script_path)}';"
            "Find-AVSignature "
            f"-StartByte {int(self.start_byte)} "
            f"-EndByte '{remote_end}' "
            f"-Interval {int(self.interval)} "
            f"-Path '{remote_target}' "
            f"-BufferLen {int(self._DEFAULT_BUFFER_LEN)} "
            f"{'-Force' if self._DEFAULT_FORCE else ''} "
            "-Verbose *>&1 | Out-String"
        )

        print_status("Running Find-AVSignature on target...")
        result = self._run_powershell(invoke)

        if self._AUTO_CLEANUP:
            self._cleanup_remote([script_path, blob_path])

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned by Find-AVSignature")

        if re.search(r"(Exception|Cannot|error|failed)", result, re.I):
            print_warning("PowerShell reported potential issues during execution")

        print_success("Find-AVSignature completed")
        print_info(result)
        return True
