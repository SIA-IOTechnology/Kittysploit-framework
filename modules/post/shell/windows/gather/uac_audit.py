#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.post.windows.uac_bypass import UacBypassMixin


class Module(Post, UacBypassMixin):
    __info__ = {
        "name": "Windows Gather UAC & Integrity Audit",
        "description": (
            "Audit UAC policy (EnableLUA, ConsentPromptBehaviorAdmin, "
            "LocalAccountTokenFilterPolicy), groups, and privileges."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "agent": {
            "risk": "passive",
            "effects": ["reconnaissance"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals"],
            "cost": 0.5,
            "noise": 0.2,
            "value": 0.8,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {"consumes_capabilities": ["shell"], "produces_capabilities": []},
        },
    }

    def run(self):
        if not self.uac_require_windows():
            return False

        print_info("=" * 60)
        print_info("UAC policy (HKLM\\...\\Policies\\System)")
        keys = [
            ("EnableLUA", "1 = UAC enabled"),
            ("ConsentPromptBehaviorAdmin", "0=never notify, 2=always notify"),
            ("PromptOnSecureDesktop", "Secure desktop for UAC prompt"),
            ("LocalAccountTokenFilterPolicy", "1=remote admin full token (dangerous)"),
        ]
        for name, hint in keys:
            out = self.uac_execute(
                f'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v {name}',
                timeout=8,
            )
            print_info(f"  {name}: {out or '(no data)'} — {hint}")

        print_info("-" * 60)
        print_info("Current integrity / groups")
        for cmd in (
            "whoami /groups",
            "whoami /priv",
            "whoami /all",
        ):
            print_info(f"$ {cmd}")
            print_info(self.uac_execute(cmd, timeout=12) or "(no output)")

        if self.uac_is_admin():
            print_success("Session appears to have administrator privileges.")
        else:
            print_status("Session is not elevated (medium integrity admin group only).")

        print_info("=" * 60)
        return True
