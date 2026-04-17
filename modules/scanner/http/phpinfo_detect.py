#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection pages phpinfo exposées."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = [
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/pi.php",
    "/dashboard/phpinfo.php",
]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "PHPInfo exposure detection",
        "description": "Detects exposed phpinfo pages that disclose PHP configuration, modules, paths, and environment details.",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["web", "scanner", "php", "phpinfo", "disclosure", "misconfiguration"],
    }

    def run(self):
        for path in PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue

            body = (r.text or "").lower()
            if "php version" in body and "php credits" in body:
                self.set_info(severity="medium", reason=f"Exposed phpinfo page at {path}")
                return True

        return False
