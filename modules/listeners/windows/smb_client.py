#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SMB client listener — connects to a remote SMB service and creates an interactive session.
"""

from kittysploit import *
from lib.protocols.smb.smb_client import SMBAuth, SMBClient


class Module(Listener):
    """SMB bind listener — file share access over authenticated SMB session."""

    __info__ = {
        "name": "SMB Client",
        "description": "Connects to a remote SMB server and creates an interactive SMB shell session",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.SMB,
        "protocol": "smb",
        "dependencies": ["pysmb"],
    }

    rhost = OptString("127.0.0.1", "Target SMB host", True)
    rport = OptPort(445, "Target SMB port", True)
    username = OptString("", "SMB username", True)
    password = OptString("", "SMB password", False)
    domain = OptString("", "SMB domain (optional)", False)
    client_name = OptString("kittysploit", "Local SMB client name", False)
    server_name = OptString("", "Remote NetBIOS name (optional, defaults to rhost)", False)
    use_ntlm_v2 = OptBool(True, "Use NTLMv2 authentication", False)

    def run(self):
        try:
            host = str(self.rhost).strip()
            port = int(self.rport)
            user = str(self.username or "").strip()
            password = str(self.password or "")
            domain = str(self.domain or "").strip()
            client_name = str(self.client_name or "kittysploit")
            server_name = str(self.server_name or "").strip() or host

            print_status(f"Connecting to SMB {host}:{port} as {domain}\\{user}" if domain else f"Connecting to SMB {host}:{port} as {user}")

            auth = SMBAuth(
                username=user,
                password=password,
                domain=domain,
                client_name=client_name,
                server_name=server_name,
            )
            client = SMBClient(
                host=host,
                port=port,
                auth=auth,
                timeout=int(self.timeout) if self.timeout else 10,
                use_ntlm_v2=bool(self.use_ntlm_v2),
                direct_tcp=True,
            )

            if not client.connect():
                print_error(f"SMB authentication or connection failed for {host}:{port}")
                return False

            shares = client.list_shares()
            print_success(f"SMB session established — {len(shares)} share(s) visible")
            if shares:
                preview = ", ".join(shares[:8])
                suffix = "..." if len(shares) > 8 else ""
                print_info(f"Shares: {preview}{suffix}")

            additional_data = {
                "host": host,
                "port": port,
                "username": user,
                "password": password,
                "domain": domain,
                "client_name": client_name,
                "server_name": server_name,
                "shares": shares,
                "platform": "windows",
            }

            return (client, host, port, additional_data)

        except Exception as e:
            print_error(f"SMB connection failed: {e}")
            return False

    def shutdown(self):
        return True
