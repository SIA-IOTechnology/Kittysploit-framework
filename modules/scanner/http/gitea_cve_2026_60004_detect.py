#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Gitea/Forgejo CVE-2026-60004 diffpatch hook RCE surface."""

from __future__ import annotations

from typing import Optional

from kittysploit import *
from lib.protocols.http.gitea_probe import GITEA_PATCHED_VERSION, Gitea
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Gitea):
    __info__ = {
        "name": "Gitea/Forgejo CVE-2026-60004 Diffpatch Detect",
        "description": (
            "Detects Gitea or Forgejo instances potentially affected by CVE-2026-60004 "
            "(unauthenticated/authenticated diffpatch git hook RCE via bare-clone add/add "
            "conflict on hooks/post-index-change). Fixed in Gitea 1.27.1."
        ),
        "author": ["Shai Rod (NightRang3r)", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-60004"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-60004",
            "https://www.cve.org/CVERecord?id=CVE-2026-60004",
        ],
        "tags": [
            "web",
            "scanner",
            "gitea",
            "forgejo",
            "git",
            "devops",
            "rce",
            "diffpatch",
            "cve-2026-60004",
            "vuln",
        ],
        "modules": ["exploits/linux/http/gitea_cve_2026_60004_diffpatch_rce"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "exploit_paths"],
            "chain": {
                "produces_capabilities": ["rce"],
                "suggested_followups": [
                    "exploits/linux/http/gitea_cve_2026_60004_diffpatch_rce",
                ],
            },
        },
    }

    port = OptPort(3000, "Gitea/Forgejo HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("", "Base URI if Gitea is not at site root", False)

    def run(self):
        probe = self.probe_gitea()
        if not probe.get("found"):
            return False

        forge = str(probe.get("forge") or "gitea")
        version = str(probe.get("version") or "")
        version_raw = str(probe.get("version_raw") or version)
        registration = self.gitea_registration_open()
        vulnerable = self.gitea_version_vulnerable(version, forge=forge)

        if vulnerable is True:
            severity = "critical"
            reason = (
                f"{forge.title()} {version or version_raw} < {GITEA_PATCHED_VERSION} "
                f"(CVE-2026-60004 diffpatch hook RCE)"
            )
        elif vulnerable is False:
            severity = "info"
            reason = (
                f"{forge.title()} {version or version_raw} >= {GITEA_PATCHED_VERSION} "
                f"(patched for CVE-2026-60004)"
            )
        else:
            severity = "high"
            reason = (
                f"{forge.title()} detected (version {version or version_raw or 'unknown'}); "
                f"CVE-2026-60004 possible if diffpatch runs in bare clone (< {GITEA_PATCHED_VERSION})"
            )

        if registration:
            reason += "; open registration observed"
        else:
            reason += "; registration closed (exploit needs credentials)"

        print_status(
            f"{forge} version={version or version_raw or 'unknown'} "
            f"vuln={vulnerable} signup={registration}"
        )
        self.set_info(
            severity=severity,
            reason=reason,
            forge=forge,
            version=version or version_raw or "unknown",
            vulnerable=vulnerable,
            registration_open=registration,
            cve="CVE-2026-60004",
            evidence=probe.get("evidence"),
        )
        return True
