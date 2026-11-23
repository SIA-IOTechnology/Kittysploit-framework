#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-116448 — Dell PowerStore SDNAS diagnostic API exposure."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.dell_powerstore import Dell_powerstore
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Dell_powerstore):
    __info__ = {
        "name": "Dell PowerStore SDNAS CVE-2026-116448 detect",
        "description": (
            "Fingerprints Dell PowerStore (application_instance), SDNAS nodes, and "
            "OS version for diagnostic command-injection preconditions (fixed 4.0.0.1)."
        ),
        "author": ["KittySploit Team", "LLCForge"],
        "severity": "critical",
        "cve": ["CVE-2026-116448"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-116448",
        ],
        "tags": ["dell", "powerstore", "sdnas", "scanner", "cve-2026-116448"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/powerstore_cve_2026_116448_sdnas_rce",
                ],
            },
        },
    }

    port = OptPort(443, "PowerStore HTTPS API port", required=False)

    _FIXED_VERSION = "4.0.0.1"

    def run(self):
        code, info = self.ps_application_instance()
        if code == 0:
            return False
        if not info or not info.get("is_powerstore"):
            return False

        version = str(info.get("version") or "unknown")
        sdnas_code, node_ids = self.ps_sdnas_nodes()
        sdnas = bool(node_ids) and sdnas_code == 200

        version_known = version not in ("", "unknown")
        patched = version_known and not self.ps_version_less_than(version, self._FIXED_VERSION)
        affected = version_known and self.ps_version_less_than(version, self._FIXED_VERSION)
        if not version_known and sdnas:
            affected = True

        if patched:
            return False
        if not sdnas:
            return False

        severity = "critical" if affected else "high"
        reason = f"PowerStore {version}, SDNAS node(s)={len(node_ids)}"
        if affected:
            reason += f" (< {self._FIXED_VERSION})"
        self.set_info(
            severity=severity,
            cve="CVE-2026-116448",
            reason=reason,
            version=version,
            sdnas_nodes=len(node_ids),
            sample_node_id=node_ids[0] if node_ids else "",
        )
        return True