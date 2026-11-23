#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-129289 — PHP-FPM FastCGI request smuggling preconditions."""

from __future__ import annotations

import re
from typing import Any, Dict, Tuple

from kittysploit import *
from lib.protocols.fcgi.client import Fastcgi
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Fastcgi):
    __info__ = {
        "name": "PHP-FPM CVE-2026-129289 detect",
        "description": (
            "Checks PHP 8.2–8.5 patch level, PHP/FPM hints, keep-alive, and optional "
            "exposed PHP-FPM TCP port for FastCGI request-smuggling RCE."
        ),
        "author": ["KittySploit Team", "LLCForge"],
        "severity": "critical",
        "cve": ["CVE-2026-129289"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-129289",
        ],
        "tags": ["php", "php-fpm", "fastcgi", "nginx", "scanner", "cve-2026-129289"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/php_fpm_cve_2026_129289_fastcgi_smuggle_rce",
                ],
            },
        },
    }

    fpm_port = OptPort(9000, "PHP-FPM TCP port to probe", required=False, advanced=True)
    probe_fpm = OptBool(True, "Probe TCP FPM port on target host", required=False)

    _PATCHED_PHP = {
        (8, 2): (8, 2, 35),
        (8, 3): (8, 3, 36),
        (8, 4): (8, 4, 27),
        (8, 5): (8, 5, 12),
    }

    @classmethod
    def _php_version_tuple(cls, text: str) -> Tuple[int, ...]:
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
        if not match:
            return ()
        return tuple(int(x) for x in match.groups())

    @classmethod
    def _php_affected(cls, version_tuple: Tuple[int, ...]) -> bool:
        if len(version_tuple) < 3 or version_tuple[:2] < (8, 2):
            return False
        patched = cls._PATCHED_PHP.get(version_tuple[:2])
        return bool(patched and version_tuple < patched)

    def _php_hints(self, response: Any) -> Dict[str, Any]:
        headers = {k.lower(): v for k, v in (response.headers or {}).items()}
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        php_hint = "php" in x_powered.lower() or "php" in server.lower()
        keepalive = "keep-alive" in headers.get("connection", "").lower()
        php_version = ""
        version_tuple: Tuple[int, ...] = ()
        body = (response.text or "")[:500]
        for src in (x_powered, server, body):
            if "PHP/" in src:
                found = re.search(r"PHP/[\d.]+", src)
                php_version = found.group() if found else src
                version_tuple = self._php_version_tuple(src)
                break
        return {
            "php_hint": php_hint,
            "keepalive": keepalive,
            "php_version": php_version,
            "version_tuple": version_tuple,
            "version_affected": self._php_affected(version_tuple),
        }

    def run(self):
        resp = self.http_request(method="GET", path=self.path or "/")
        if not resp or int(resp.status_code or 0) >= 500:
            return False

        hints = self._php_hints(resp)
        fpm_open = self.fcgi_tcp_open() if self.probe_fpm else False

        if not hints["php_hint"] and not hints["version_affected"] and not fpm_open:
            return False

        reasons = []
        if hints["version_affected"]:
            reasons.append(f"affected PHP {hints['php_version'] or hints['version_tuple']}")
        elif hints["version_tuple"]:
            reasons.append(f"patched PHP {hints['php_version'] or hints['version_tuple']}")
        elif hints["php_hint"]:
            reasons.append("PHP stack detected")
        if hints["keepalive"]:
            reasons.append("HTTP keep-alive")
        if fpm_open:
            reasons.append(f"FPM TCP {self.fcgi_target_port()} open")

        severity = "critical" if (hints["version_affected"] and (hints["keepalive"] or fpm_open)) else "high"
        if hints["version_affected"] or (hints["php_hint"] and hints["keepalive"]):
            self.set_info(
                severity=severity,
                cve="CVE-2026-129289",
                reason="; ".join(reasons) or "PHP-FPM smuggle preconditions",
                php_version=hints["php_version"] or "unknown",
                keepalive=hints["keepalive"],
                fpm_tcp_open=fpm_open,
            )
            return True
        if fpm_open and hints["php_hint"]:
            self.set_info(
                severity="high",
                cve="CVE-2026-129289",
                reason="; ".join(reasons),
                fpm_tcp_open=True,
            )
            return True
        return False