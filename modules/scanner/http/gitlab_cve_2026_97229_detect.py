#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-97229 — GitLab CI regexp compiler advisory range."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "GitLab CVE-2026-97229 detect",
        "description": (
            "Flags self-managed GitLab 19.2–19.4 before patch releases; "
            "exploitation needs a writable public project and CI lint trigger."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-97229"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-97229",
            "https://github.com/jburgess-r7/CVE-2026-97229-PoC",
        ],
        "tags": ["gitlab", "ci", "regexp", "cve-2026-97229"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/gitlab_cve_2026_97229_rce",
                    "scanner/http/gitlab_detect",
                ],
            },
        },
    }

    _VERSION_RE = re.compile(
        r"(?:gitlab[_-]?ce|gitlab[_-]?ee|version)[^\d]*(\d+\.\d+\.\d+)",
        re.I,
    )

    def _parse(self, version: str) -> tuple[int, int, int]:
        nums = [int(x) for x in version.split(".")[:3]]
        while len(nums) < 3:
            nums.append(0)
        return nums[0], nums[1], nums[2]

    def _affected(self, version: str) -> bool:
        major, minor, patch = self._parse(version)
        if major != 19:
            return False
        if minor == 2 and patch < 8:
            return True
        if minor == 3 and patch < 5:
            return True
        if minor == 4 and patch < 2:
            return True
        return False

    def run(self):
        for path in ("/help", "/api/v4/version", "/users/sign_in"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            text = r.text or ""
            if path == "/api/v4/version":
                m = re.search(r'"version"\s*:\s*"([^"]+)"', text)
                if m and self._affected(m.group(1)):
                    self.set_info(
                        severity="critical",
                        cve="CVE-2026-97229",
                        reason=f"GitLab {m.group(1)} in advisory range",
                        version=m.group(1),
                    )
                    return True
            m = self._VERSION_RE.search(text)
            if m and self._affected(m.group(1)):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-97229",
                    reason=f"GitLab {m.group(1)} in advisory range",
                    version=m.group(1),
                )
                return True
        return False