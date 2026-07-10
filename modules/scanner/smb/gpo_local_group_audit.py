#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Audit privileged local group assignments configured via GPO on SYSVOL."""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from kittysploit import *
from lib.protocols.gpo.analyser import GpoGroupAnalyser
from lib.protocols.gpo.processors.groups import build_processed_gpo
from lib.protocols.gpo.sysvol import (
    download_gpo_bytes,
    download_gpo_text,
    extract_gpo_guid,
    list_gpo_policy_files,
    parse_gpo_file,
    policy_type_for_path,
)
from lib.protocols.smb.smb_client import SMBAuth, SMBClient
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "GPO Local Group Audit",
        "description": (
            "Parse SYSVOL GPO files (Groups.xml, GptTmpl.inf) and detect trustees "
            "added to privileged local groups (Administrators, RDP Users, etc.)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["smb", "gpo", "windows", "ad", "privesc", "scanner"],
        "references": [
            "https://github.com/cogiceo/GPOHound",
            "https://bloodhound.specterops.io/resources/edges/admin-to",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "gpo_local_admin", "gpo_can_rdp", "gpo_samaccountname_hijack"],
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

        analyser = GpoGroupAnalyser()
        gpo_cache: Dict[str, Dict[str, Dict[str, object]]] = {}
        gpo_sources: Dict[str, List[str]] = {}

        for auth in self._auth_profiles():
            client = SMBClient(host=host, port=self._port(), auth=auth, timeout=int(self._timeout()))
            if not client.connect():
                continue
            connected = True
            if "SYSVOL" not in client.list_shares():
                client.close()
                continue

            targets = list_gpo_policy_files(client, domain, max_gpos=limit, category="groups")
            print_info(f"Inspecting {len(targets)} GPO file(s) under SYSVOL")

            for gpo_guid, remote_path in targets:
                if remote_path.lower().endswith(".pol"):
                    content = download_gpo_bytes(client, remote_path)
                else:
                    content = download_gpo_text(client, remote_path)
                parsed = parse_gpo_file(remote_path, content, modes=("groups",))
                if not parsed:
                    continue

                guid = gpo_guid or extract_gpo_guid(remote_path)
                bucket = gpo_cache.setdefault(guid, {})
                gpo_sources.setdefault(guid, []).append(remote_path)
                for filename, content in parsed.items():
                    if filename == "Groups.xml":
                        scope = policy_type_for_path(remote_path).lower()
                        bucket.setdefault(f"Groups.xml::{scope}", content)
                    else:
                        bucket[filename] = content

            for guid, bucket in gpo_cache.items():
                normalized = {
                    "GptTmpl.inf": bucket.get("GptTmpl.inf"),
                    "Groups.xml": None,
                }
                for scope in ("machine", "user"):
                    scoped = bucket.get(f"Groups.xml::{scope}")
                    if scoped:
                        normalized[f"Groups.xml::{scope}"] = scoped

                for policy_type in ("Machine", "User"):
                    parsed_files = {"GptTmpl.inf": normalized.get("GptTmpl.inf") or {}}
                    scoped_key = f"Groups.xml::{policy_type.lower()}"
                    if normalized.get(scoped_key):
                        parsed_files["Groups.xml"] = normalized[scoped_key]
                    processed = build_processed_gpo(parsed_files, policy_type)
                    analysis = analyser.analyse(processed, gpo_guid=guid)
                    if not analysis:
                        continue

                    for scope, rows in analysis.items():
                        for row in rows:
                            findings.append({
                                "gpo_guid": guid,
                                "source": gpo_sources.get(guid, []),
                                "policy_type": scope,
                                "group": row.get("name"),
                                "group_sid": row.get("sid"),
                                "edge": row.get("edge"),
                                "members": row.get("Members") or [],
                                "hijackable": row.get("Hijackable") or {},
                                "analysis": row.get("analysis"),
                                "references": row.get("references"),
                            })
                            print_warning(
                                f"{guid} [{scope}] {row.get('edge')} via {row.get('name')} "
                                f"({len(row.get('Members') or [])} member(s))"
                            )

            client.close()
            if findings or gpo_cache:
                break

        if not connected:
            print_error("SMB connection failed")
            return False

        if not findings:
            print_info("No privileged local group assignments found in inspected GPO files")
            return False

        self.set_info(
            severity="high",
            reason=f"{len(findings)} privileged local group assignment(s) found via GPO",
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
