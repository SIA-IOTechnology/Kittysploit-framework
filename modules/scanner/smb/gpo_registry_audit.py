#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Audit insecure registry settings configured via GPO on SYSVOL."""

from __future__ import annotations

import json
from typing import Dict, List

from kittysploit import *
from lib.protocols.gpo.analysers.registry import GpoRegistryAnalyser
from lib.protocols.gpo.processors.registry import build_registry_processed
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
        "name": "GPO Registry Audit",
        "description": (
            "Parse SYSVOL GPO registry settings (Registry.xml, registry.pol) and detect "
            "relay-friendly SMB/NTLM policies, autologon passwords, and stored credentials."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["smb", "gpo", "windows", "ad", "registry", "scanner"],
        "references": [
            "https://github.com/cogiceo/GPOHound",
            "https://www.thehacker.recipes/ad/movement/ntlm/relay",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": [
                "risk_signals",
                "gpo_smb_signing_disabled",
                "gpo_ntlmv1_enabled",
                "gpo_stored_credentials",
            ],
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
        analyser = GpoRegistryAnalyser()
        gpo_cache: Dict[str, Dict[str, object]] = {}

        for auth in self._auth_profiles():
            client = SMBClient(host=host, port=self._port(), auth=auth, timeout=int(self._timeout()))
            if not client.connect():
                continue
            connected = True
            if "SYSVOL" not in client.list_shares():
                client.close()
                continue

            targets = list_gpo_policy_files(client, domain, max_gpos=limit, category="registry")
            print_info(f"Inspecting {len(targets)} registry GPO file(s) under SYSVOL")

            for _, remote_path in targets:
                if remote_path.lower().endswith(".pol"):
                    content = download_gpo_bytes(client, remote_path)
                else:
                    content = download_gpo_text(client, remote_path)
                parsed = parse_gpo_file(remote_path, content, modes=("registry",))
                if not parsed:
                    continue

                guid = extract_gpo_guid(remote_path)
                bucket = gpo_cache.setdefault(guid, {})
                policy_type = policy_type_for_path(remote_path)
                for filename, payload in parsed.items():
                    if filename == "Registry.xml":
                        bucket.setdefault(f"Registry.xml::{policy_type.lower()}", payload)
                    elif filename == "registry.pol":
                        bucket.setdefault(f"registry.pol::{policy_type.lower()}", payload)
                    elif filename == "GptTmpl.inf":
                        bucket["GptTmpl.inf"] = payload

            for guid, bucket in gpo_cache.items():
                for policy_type in ("Machine", "User"):
                    parsed_files: Dict[str, object] = {}
                    scoped_xml = bucket.get(f"Registry.xml::{policy_type.lower()}")
                    scoped_pol = bucket.get(f"registry.pol::{policy_type.lower()}")
                    if scoped_xml:
                        parsed_files["Registry.xml"] = scoped_xml
                    if scoped_pol:
                        parsed_files["registry.pol"] = scoped_pol
                    if policy_type == "Machine" and bucket.get("GptTmpl.inf"):
                        parsed_files["GptTmpl.inf"] = bucket["GptTmpl.inf"]

                    processed = build_registry_processed(parsed_files, policy_type)
                    analysis = analyser.analyse(processed)
                    for scope, rows in analysis.items():
                        for row in rows:
                            findings.append({
                                "gpo_guid": guid,
                                "policy_type": scope,
                                "analysis": row.get("analysis"),
                                "regkey": row.get("regkey"),
                                "value": row.get("value"),
                                "decrypted": row.get("decrypted"),
                                "bloodhound_property": row.get("bloodhound_property"),
                                "references": row.get("references"),
                            })
                            print_warning(f"{guid} [{scope}] {row.get('analysis')}")

            client.close()
            if findings or gpo_cache:
                break

        if not connected:
            print_error("SMB connection failed")
            return False
        if not findings:
            print_info("No risky registry settings found in inspected GPO files")
            return False

        self.set_info(
            severity="high",
            reason=f"{len(findings)} risky GPO registry setting(s) found",
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
