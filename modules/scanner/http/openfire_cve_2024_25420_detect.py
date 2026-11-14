#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2024-25420 — stale admin.authorizedJIDs after admin deletion."""

import re
import socket

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Openfire CVE-2024-25420 detect",
        "description": (
            "Openfire < 4.8.1 with XEP-0077 registration may allow stale deleted "
            "administrator usernames to regain admin console access."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2024-25420"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-25420",
            "https://github.com/advisories/GHSA-5xvc-rwv8-86p7",
        ],
        "tags": ["openfire", "xmpp", "privilege-escalation", "cve-2024-25420"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/openfire_cve_2024_25420_stale_admin",
                ],
            },
        },
    }

    port = OptPort(9090, "Openfire admin HTTP port", required=False)
    xmpp_port = OptPort(5222, "XMPP client port", required=False)

    _VERSION_RE = re.compile(r"Openfire,\s*Version:\s*(\d+(?:\.\d+)+)", re.I)

    def _openfire_version(self) -> str:
        for path in ("/", "/login.jsp"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or int(r.status_code) != 200:
                continue
            match = self._VERSION_RE.search(r.text or "")
            if match:
                return match.group(1)
        return ""

    def _registration_offered(self) -> bool:
        host = str(self.rhost or "").strip()
        port = int(self.xmpp_port or 5222)
        sock = socket.create_connection((host, port), timeout=8)
        try:
            sock.sendall(
                (
                    "<?xml version='1.0'?>"
                    f"<stream:stream xmlns='jabber:client' "
                    "xmlns:stream='http://etherx.jabber.org/streams' "
                    f"version='1.0' to='{host}'>"
                ).encode()
            )
            buf = b""
            while b"</stream:features>" not in buf and len(buf) < 8192:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                buf += chunk
            return b"register" in buf
        except OSError:
            return False
        finally:
            sock.close()

    @staticmethod
    def _lt_481(version: str) -> bool:
        parts = (version or "").split(".")
        if len(parts) < 3:
            return False
        try:
            major, minor, patch = (int(parts[0]), int(parts[1]), int(re.match(r"\d+", parts[2]).group()))
        except (ValueError, AttributeError):
            return False
        if major < 4:
            return True
        if major > 4:
            return False
        if minor < 8:
            return True
        if minor > 8:
            return False
        return patch < 1

    def run(self):
        version = self._openfire_version()
        if not version:
            return False
        reg = self._registration_offered()
        vulnerable_branch = self._lt_481(version)
        if vulnerable_branch and reg:
            self.set_info(
                severity="high",
                cve="CVE-2024-25420",
                reason="Openfire registration + version before 4.8.1",
                version=version,
            )
            return True
        if vulnerable_branch:
            self.set_info(
                severity="medium",
                cve="CVE-2024-25420",
                reason=f"Openfire {version} < 4.8.1 (registration not confirmed on XMPP port)",
            )
            return True
        return False