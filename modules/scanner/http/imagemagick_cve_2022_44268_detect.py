#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects ImageMagick/GraphicsMagick conversion endpoints (filename read primitive)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ImageMagick CVE-2022-44268 Detect",
        "description": "Detects ImageMagick/GraphicsMagick conversion endpoints (filename read primitive).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2022-44268"],
        "tags": ["scanner", "web", "imagemagick", "cve-2022-44268"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-44268"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/imagemagick_cve_2022_44268_fileread"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if any(x in body for x in ("imagemagick", "graphicsmagick", "convert", "upload")):
            self.set_info(severity="high", cve="CVE-2022-44268", reason="Image conversion/upload surface hint", confidence="low")
            return True
        return False
