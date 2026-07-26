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
    username = OptString("", "SMB username (empty for null/guest auth)", False)
    password = OptString("", "SMB password", False)
    domain = OptString("", "SMB domain (optional)", False)
    auth_profile = OptChoice(
        "auto",
        "SMB auth profile: auto, credentials, null, guest",
        False,
        choices=["auto", "credentials", "null", "guest"],
    )
    client_name = OptString("kittysploit", "Local SMB client name", False)
    server_name = OptString("", "Remote NetBIOS name (optional, defaults to rhost)", False)
    use_ntlm_v2 = OptBool(True, "Use NTLMv2 authentication", False)
    validate_readable_share = OptBool(
        True,
        "In auto auth, prefer a profile that can list a non-admin share",
        False,
        advanced=True,
    )

    def _auth_candidates(self, user, password, domain, client_name, server_name):
        profile = str(self.auth_profile or "auto").strip().lower()
        if profile == "credentials":
            if not user:
                print_warning("auth_profile=credentials selected but username is empty")
            return [
                (
                    "credentials",
                    SMBAuth(
                        username=user,
                        password=password,
                        domain=domain,
                        client_name=client_name,
                        server_name=server_name,
                    ),
                )
            ]
        if profile == "null":
            if user or password or domain:
                print_warning("auth_profile=null ignores username, password, and domain options")
            return [
                (
                    "null session",
                    SMBAuth(
                        username="",
                        password="",
                        domain="",
                        client_name=client_name,
                        server_name=server_name,
                    ),
                )
            ]
        if profile == "guest":
            return [
                (
                    "guest",
                    SMBAuth(
                        username="guest",
                        password="",
                        domain=domain,
                        client_name=client_name,
                        server_name=server_name,
                    ),
                )
            ]

        if user or password:
            return [
                (
                    "credentials",
                    SMBAuth(
                        username=user,
                        password=password,
                        domain=domain,
                        client_name=client_name,
                        server_name=server_name,
                    ),
                )
            ]

        return [
            (
                "null session",
                SMBAuth(
                    username="",
                    password="",
                    domain="",
                    client_name=client_name,
                    server_name=server_name,
                ),
            ),
            (
                "guest",
                SMBAuth(
                    username="guest",
                    password="",
                    domain=domain,
                    client_name=client_name,
                    server_name=server_name,
                ),
            ),
        ]

    def _content_shares(self, shares):
        return [
            share
            for share in shares
            if share and share.upper() != "IPC$" and not share.endswith("$")
        ]

    def _first_readable_share(self, client, shares):
        for share in self._content_shares(shares):
            if client.can_list_path(share, "\\"):
                return share
        return ""

    def run(self):
        try:
            host = str(self.rhost).strip()
            port = int(self.rport)
            user = str(self.username or "").strip()
            password = str(self.password or "")
            domain = str(self.domain or "").strip()
            client_name = str(self.client_name or "kittysploit")
            server_name = str(self.server_name or "").strip() or host

            client = None
            auth_label = ""
            auth = None
            shares = []
            profile = str(self.auth_profile or "auto").strip().lower()
            candidates = self._auth_candidates(
                user,
                password,
                domain,
                client_name,
                server_name,
            )
            for index, (label, candidate_auth) in enumerate(candidates):
                identity = candidate_auth.username
                if candidate_auth.domain and identity:
                    identity = f"{candidate_auth.domain}\\{identity}"
                print_status(
                    f"Connecting to SMB {host}:{port} via {label}"
                    + (f" as {identity}" if identity else "")
                )
                candidate = SMBClient(
                    host=host,
                    port=port,
                    auth=candidate_auth,
                    timeout=int(self.timeout) if self.timeout else 10,
                    use_ntlm_v2=bool(self.use_ntlm_v2),
                    direct_tcp=True,
                )
                if candidate.connect():
                    candidate_shares = candidate.list_shares()
                    if (
                        profile == "auto"
                        and bool(self.validate_readable_share)
                        and self._content_shares(candidate_shares)
                    ):
                        readable_share = self._first_readable_share(candidate, candidate_shares)
                        if not readable_share and index < len(candidates) - 1:
                            print_warning(
                                f"{label} connected but no non-admin share was readable; trying next profile"
                            )
                            candidate.close()
                            continue
                        if readable_share:
                            print_info(f"{label} can list share: {readable_share}")
                    client = candidate
                    auth_label = label
                    auth = candidate_auth
                    shares = candidate_shares
                    break
                candidate.close()

            if not client or not auth:
                print_error(f"SMB authentication or connection failed for {host}:{port}")
                return False

            print_success(f"SMB session established via {auth_label} - {len(shares)} share(s) visible")
            if shares:
                preview = ", ".join(shares[:8])
                suffix = "..." if len(shares) > 8 else ""
                print_info(f"Shares: {preview}{suffix}")

            additional_data = {
                "host": host,
                "port": port,
                "username": auth.username,
                "password": auth.password,
                "domain": auth.domain,
                "auth_profile": auth_label,
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
