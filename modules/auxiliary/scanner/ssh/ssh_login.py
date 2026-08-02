#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Compatibility alias for ``auxiliary/scanner/ssh/ssh_login_bruteforce``.

Prefer the bruteforce module path for new chains and workflows.
"""

from modules.auxiliary.scanner.ssh.ssh_login_bruteforce import Module as SSHLoginBruteforce


class Module(SSHLoginBruteforce):
    TYPE_MODULE = "auxiliary"
    __info__ = {
        "name": "SSH login",
        "description": (
            "Compatibility alias for auxiliary/scanner/ssh/ssh_login_bruteforce. "
            "Attempts common and wordlist-based SSH credentials and registers "
            "an interactive SSH session on success."
        ),
        "author": "KittySploit Team",
        "tags": ["ssh", "linux", "credentials", "bruteforce", "scanner", "session"],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_spray", "network_probe"],
            "expected_requests": 40,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "chain": {
                "consumes_capabilities": ["service_identified", "ssh_auth_surface"],
                "produces_capabilities": [
                    {"capability": "ssh_access", "from_detail": "username"},
                    "authenticated_session",
                    "shell",
                ],
                "option_bindings": {},
                "suggested_followups": [
                    "post/shell/linux/gather/enum_system",
                    "post/shell/linux/gather/check_sudo",
                ],
            },
        },
    }

    def run(self):
        return super().run()
