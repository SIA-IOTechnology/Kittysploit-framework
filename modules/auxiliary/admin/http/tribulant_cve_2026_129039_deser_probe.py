#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-129039 — Tribulant Newsletters unsafe unserialize probe."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.tribulant_newsletters import Tribulant_newsletters


class Module(Auxiliary, Http_client, Tribulant_newsletters):
    __info__ = {
        "name": "Tribulant CVE-2026-129039 deserialization probe",
        "description": "Sends benign serialized payload to newsletters AJAX handlers.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-129039"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-129039"],
        "tags": ["wordpress", "tribulant", "deserialization", "cve-2026-129039", "auxiliary"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["scanner/http/tribulant_cve_2026_129039_detect"],
            },
        },
    }

    param_name = OptString("data", "POST field passed to unserialize()", required=False)
    probe_payload = OptString(
        'O:8:"stdClass":0:{}',
        "PHP serialized probe (not a gadget chain)",
        required=False,
        advanced=True,
    )

    def run(self):
        payload = str(self.probe_payload or 'O:8:"stdClass":0:{}')
        param = str(self.param_name or "data")
        hit = self.newsletters_deser_probe(payload, param=param)
        if not hit:
            print_error("No deserialization indicator")
            return False
        print_success(f"Indicator on {hit['endpoint']} (HTTP {hit['status_code']})")
        self.set_info(severity="critical", cve="CVE-2026-129039", **hit)
        return True