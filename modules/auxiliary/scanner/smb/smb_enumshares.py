#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Énumération des partages SMB (NetShareEnum via pysmb)."""

import socket
from typing import Any, Dict, List, Optional, Tuple

from kittysploit import *
from lib.protocols.smb.smb_client import SMBAuth, SMBClient
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Auxiliary, Smb_scanner_client):

    DEFAULT_TIMEOUT = 10
    ADMIN_SHARE_SUFFIX = "$"
    SKIP_CONTENT_SHARES = frozenset({"IPC$"})

    __info__ = {
        "name": "SMB enumshares",
        "description": (
            "Connects over SMB (null session, guest, or supplied credentials) and lists "
            "available shares with optional top-level directory listing."
        ),
        "author": "KittySploit Team",
        "tags": ["smb", "auxiliary", "enumeration", "shares", "windows", "enumshares"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.0,
        },
    }

    username = OptString("", "SMB username (if empty, null/guest profiles are tried)", required=False)
    password = OptString("", "SMB password", required=False)
    domain = OptString("", "SMB domain or workgroup", required=False)
    try_null = OptBool(True, "Try anonymous null session when no username is set", required=False)
    try_guest = OptBool(True, "Try guest account when no username is set", required=False)
    enumerate_contents = OptBool(
        False,
        "List top-level entries for each readable share",
        required=False,
        advanced=True,
    )
    smb_timeout = OptInteger(
        DEFAULT_TIMEOUT,
        "SMB connection and operation timeout in seconds",
        required=False,
        advanced=True,
    )

    def _opt(self, name: str, default: Any = "") -> Any:
        value = getattr(self, name, default)
        if hasattr(value, "value"):
            return value.value
        return value

    def _timeout_seconds(self) -> int:
        return max(int(self._opt("smb_timeout", self.DEFAULT_TIMEOUT) or self.DEFAULT_TIMEOUT), 3)

    def _auth_profiles(self) -> List[Tuple[str, SMBAuth]]:
        user = str(self._opt("username", "") or "").strip()
        password = str(self._opt("password", "") or "")
        domain = str(self._opt("domain", "") or "").strip()

        if user or password:
            return [("credentials", SMBAuth(username=user, password=password, domain=domain))]

        profiles: List[Tuple[str, SMBAuth]] = []
        if bool(self._opt("try_null", True)):
            profiles.append(("null session", SMBAuth(username="", password="", domain="")))
        if bool(self._opt("try_guest", True)):
            profiles.append(("guest", SMBAuth(username="guest", password="", domain="")))
        return profiles

    def _connect(self, label: str, auth: SMBAuth) -> Optional[SMBClient]:
        host = self._host()
        if not host:
            return None
        client = SMBClient(
            host=host,
            port=self._port(),
            auth=auth,
            timeout=self._timeout_seconds(),
            use_ntlm_v2=True,
            direct_tcp=True,
        )
        if client.connect():
            print_success(f"SMB authenticated via {label}")
            return client
        client.close()
        return None

    def _share_records(self, client: SMBClient) -> List[Dict[str, Any]]:
        client._require()
        records: List[Dict[str, Any]] = []
        try:
            share_objs = client.conn.listShares(timeout=self._timeout_seconds())
        except Exception as exc:
            print_error(f"listShares failed: {exc}")
            return records

        for share in share_objs:
            name = (share.name or "").rstrip("\x00").strip()
            if not name:
                continue
            comments = (getattr(share, "comments", "") or "").strip()
            share_type = getattr(share, "type", None)
            records.append(
                {
                    "name": name,
                    "type": share_type,
                    "comments": comments,
                    "admin": name.endswith(self.ADMIN_SHARE_SUFFIX),
                }
            )
        return records

    def _print_share(self, record: Dict[str, Any]) -> None:
        label = record["name"]
        if record.get("admin"):
            label += " (admin)"
        comment = record.get("comments") or ""
        share_type = record.get("type")
        extra = []
        if comment:
            extra.append(comment)
        if share_type is not None:
            extra.append(f"type={share_type}")
        suffix = f" - {', '.join(extra)}" if extra else ""
        print_info(f"  {label}{suffix}")

    def _enumerate_share_root(self, client: SMBClient, share: str) -> None:
        entries = client.list_path(share, "\\")
        if not entries:
            print_info(f"    [{share}] no readable entries or access denied")
            return
        for entry in entries[:50]:
            kind = "dir" if entry.get("is_dir") else "file"
            size = entry.get("size", 0)
            print_info(f"    [{share}] {entry.get('name')} ({kind}, {size} bytes)")
        if len(entries) > 50:
            print_info(f"    [{share}] ... {len(entries) - 50} more entries")

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        try:
            with socket.create_connection((host, self._port()), timeout=self._timeout_seconds()):
                pass
            return {
                "vulnerable": True,
                "reason": f"SMB port {self._port()} reachable on {host}",
                "confidence": "low",
            }
        except OSError as exc:
            return {"vulnerable": False, "reason": str(exc), "confidence": "high"}

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target host is required")
            return False

        profiles = self._auth_profiles()
        if not profiles:
            print_error("No authentication profile configured")
            return False

        client: Optional[SMBClient] = None
        auth_label = ""
        for label, auth in profiles:
            print_status(f"Trying SMB auth profile: {label}")
            client = self._connect(label, auth)
            if client:
                auth_label = label
                break

        if not client:
            print_error("SMB authentication failed for all configured profiles")
            return False

        try:
            shares = self._share_records(client)
            if not shares:
                print_warning("Connected but no shares were returned")
                return False

            print_success(
                f"Found {len(shares)} share(s) on {host}:{self._port()} via {auth_label}"
            )
            for record in shares:
                self._print_share(record)

            if bool(self._opt("enumerate_contents", False)):
                print_status("Listing top-level entries for readable shares...")
                for record in shares:
                    name = record["name"]
                    if name.upper() in self.SKIP_CONTENT_SHARES:
                        continue
                    self._enumerate_share_root(client, name)

            return True
        finally:
            client.close()
