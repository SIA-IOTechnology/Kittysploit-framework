#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Audit dangerous User Rights Assignment configured via GPO on SYSVOL."""

from __future__ import annotations

import json
from typing import Dict, List

from kittysploit import *
from lib.protocols.gpo.analysers.privilege_rights import GpoPrivilegeRightsAnalyser
from lib.protocols.gpo.processors.privilege_rights import process_privilege_rights
from lib.protocols.gpo.sysvol import (
    download_gpo_text,
    extract_gpo_guid,
    list_gpo_policy_files,
    parse_gpo_file,
)
from lib.protocols.smb.smb_client import SMBAuth, SMBClient
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "GPO Privilege Rights Audit",
        "description": (
            "Parse SYSVOL GptTmpl.inf User Rights Assignment and detect trustees "
            "with dangerous privileges (SeDebug, SeImpersonate, SeBackup, etc.)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["smb", "gpo", "windows", "ad", "privesc", "scanner"],
        "references": [
            "https://github.com/cogiceo/GPOHound",
            "https://gtworek.github.io/Priv2Admin/",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "gpo_privilege_escalation"],
        },
    }

    domain = OptString("", "AD DNS domain name (e.g. corp.local)", required=True)
    username = OptString("", "SMB username (empty tries null/guest)", required=False)
    password = OptString("", "SMB password", required=False)
    max_gpos = OptInteger(50, "Maximum GPO folders to inspect", required=False)
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

    def run(self):
        host = self._host()
        domain = str(self.domain or "").strip().lower()
        if not host or not domain:
            print_error("Target and domain are required")
            return False

        limit = max(1, int(self.max_gpos or 50))
        findings: List[Dict[str, object]] = []
        connected = False
        analyser = GpoPrivilegeRightsAnalyser()

        for auth in self._auth_profiles():
            client = SMBClient(host=host, port=self._port(), auth=auth, timeout=int(self._timeout()))
            if not client.connect():
                continue
            connected = True
            if "SYSVOL" not in client.list_shares():
                client.close()
                continue

            targets = list_gpo_policy_files(client, domain, max_gpos=limit, category="privilege")
            print_info(f"Inspecting {len(targets)} privilege GPO file(s) under SYSVOL")

            for _, remote_path in targets:
                content = download_gpo_text(client, remote_path)
                parsed = parse_gpo_file(remote_path, content, modes=("privilege",))
                if not parsed:
                    continue
                guid = extract_gpo_guid(remote_path)
                gpttmpl = parsed.get("GptTmpl.inf", {})
                privileges = gpttmpl.get("Privilege Rights") if isinstance(gpttmpl, dict) else None
                if not privileges:
                    continue
                processed = process_privilege_rights(privileges)
                analysis = analyser.analyse(processed)
                for row in analysis:
                    findings.append({
                        "gpo_guid": guid,
                        "source": remote_path,
                        **row,
                    })
                    print_warning(
                        f"{guid} {row.get('privilege')} -> "
                        f"{len(row.get('trustees') or [])} non-default trustee(s)"
                    )

            client.close()
            if findings:
                break

        if not connected:
            print_error("SMB connection failed")
            return False
        if not findings:
            print_info("No dangerous privilege rights assignments found in inspected GPO files")
            return False

        self.set_info(
            severity="high",
            reason=f"{len(findings)} dangerous GPO privilege right(s) found",
            findings=findings[:30],
        )
        if self.output_file:
            try:
                with open(str(self.output_file), "w", encoding="utf-8") as fp:
                    json.dump({"findings": findings}, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return True
