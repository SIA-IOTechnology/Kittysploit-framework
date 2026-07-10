#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64


class Module(Post):
    __info__ = {
        "name": "Windows Token Impersonation Helper",
        "description": "Basic Incognito-style token and privilege audit with optional RunAs test",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL, SessionType.WINRM],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation', 'privilege_escalation'],
        'expected_requests': 3,
        'reversible': True,
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
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    list_system_processes = OptBool(True, "List processes running as SYSTEM", False)
    runas_command = OptString("", "Optional command to launch via Start-Process -Verb RunAs", False)
    dry_run = OptBool(True, "Do not launch RunAs unless explicitly disabled", False)

    IMPERSONATION_PRIVS = (
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege",
        "SeDebugPrivilege",
        "SeCreateTokenPrivilege",
    )

    def _execute_cmd(self, command: str) -> str:
        output = self.cmd_execute(command)
        return output.strip() if output else ""

    def _run_powershell(self, script: str) -> str:
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        return self._execute_cmd(f"powershell -NoP -NonI -W Hidden -EncodedCommand {encoded}")

    def _audit_script(self) -> str:
        return r"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Output '=== Current identity ==='
whoami /user
whoami /groups
Write-Output ''
Write-Output '=== Privileges ==='
whoami /priv
Write-Output ''
Write-Output '=== Integrity ==='
whoami /groups | Select-String -Pattern 'Mandatory Label'
"""

    def _system_process_script(self) -> str:
        return r"""
$ErrorActionPreference = 'SilentlyContinue'
Get-CimInstance Win32_Process |
    Where-Object { $_.Name -match '\.exe$' } |
    ForEach-Object {
        $owner = $null
        try { $owner = ($_.GetOwner()).User } catch {}
        if ($owner -match 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE' -or $_.Name -match 'spoolsv|lsass|services') {
            [PSCustomObject]@{ PID = $_.ProcessId; Name = $_.Name; Owner = $owner }
        }
    } |
    Sort-Object Name |
    Select-Object -First 40 |
    Format-Table -AutoSize |
    Out-String
"""

    def _parse_privileges(self, text: str) -> list:
        enabled = []
        for line in (text or "").splitlines():
            if "Enabled" not in line:
                continue
            for priv in self.IMPERSONATION_PRIVS:
                if priv.lower() in line.lower():
                    enabled.append(priv)
        return enabled

    def run(self):
        print_info("=" * 80)
        print_status("Token impersonation audit")

        audit = self._run_powershell(self._audit_script())
        if audit:
            for line in audit.splitlines():
                print_info(line)

        privs = self._parse_privileges(audit)
        print_info("-" * 80)
        print_status("Impersonation-relevant privileges")
        if privs:
            for priv in privs:
                print_success(f"  Enabled: {priv}")
            if "SeImpersonatePrivilege" in privs or "SeAssignPrimaryTokenPrivilege" in privs:
                print_info("  Hint: Potato-family / PrintSpoofer / RoguePotato may apply from service accounts.")
        else:
            print_warning("  No classic impersonation privileges enabled in current token")

        if self.list_system_processes:
            print_info("-" * 80)
            print_status("Interesting SYSTEM / service processes")
            procs = self._run_powershell(self._system_process_script())
            if procs:
                for line in procs.splitlines()[:45]:
                    if line.strip():
                        print_info(f"  {line}")

        command = str(self.runas_command or "").strip()
        if command:
            print_info("-" * 80)
            if self.dry_run:
                print_warning(f"Dry run — would RunAs: {command}")
            else:
                print_status(f"Launching RunAs: {command}")
                ps = (
                    "$ErrorActionPreference='Stop';"
                    f"Start-Process -FilePath 'cmd.exe' -ArgumentList '/c {command.replace('\"', '`\"')}' -Verb RunAs"
                )
                result = self._run_powershell(ps)
                if result:
                    print_info(result)

        print_info("=" * 80)
        print_success("Token impersonation helper completed")
        return True
