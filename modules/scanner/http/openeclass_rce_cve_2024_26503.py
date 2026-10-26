#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from bs4 import BeautifulSoup
import re


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Open eClass RCE (CVE-2024-26503) Detection",
        "description": (
            "Detects GUnet Open eClass 3.15 instances potentially vulnerable to "
            "CVE-2024-26503 (unrestricted badge icon upload leading to RCE)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2024-26503",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26503",
            "https://www.less-secure.com/2024/03/open-eclass-cve-2024-26503-unrestricted.html",
            "https://github.com/RoboGR00t/Exploit-CVE-2024-26503",
        ],
        "modules": [
            "exploits/http/openeclass_rce_cve_2024_26503",
        ],
        "tags": ["web", "scanner", "openeclass", "rce", "cve-2024-26503"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "rce", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    def _version_tuple(self, version: str) -> tuple:
        out = []
        for token in str(version).split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            out.append(int(digits) if digits else 0)
        while len(out) < 3:
            out.append(0)
        return tuple(out[:3])

    def _is_vulnerable_version(self, version: str) -> bool:
        major, minor, _patch = self._version_tuple(version)
        return major == 3 and minor == 15

    def _extract_version(self, content: str) -> str | None:
        version_match = re.search(r"Open\s+eClass\s+([\d\.]+)", content, re.IGNORECASE)
        if version_match:
            return version_match.group(1)

        soup = BeautifulSoup(content, "html.parser")
        generator = soup.find("meta", {"name": "generator"})
        if generator and "openeclass" in generator.get("content", "").lower():
            gen_match = re.search(r"([\d\.]+)", generator.get("content", ""))
            if gen_match:
                return gen_match.group(1)
        return None

    def run(self):
        try:
            response = self.http_request(method="GET", path="/")
            if not response or response.status_code != 200:
                return False

            content = response.text or ""
            lowered = content.lower()
            if "openeclass" not in lowered and "open eclass" not in lowered:
                return False

            version = self._extract_version(content)
            if version:
                print_info(f"Open eClass version {version} detected")
                if self._is_vulnerable_version(version):
                    self.set_info(
                        severity="critical",
                        cve="CVE-2024-26503",
                        reason=(
                            f"Open eClass {version} matches the affected 3.15 line "
                            "(CVE-2024-26503 unrestricted certbadge upload)."
                        ),
                    )
                    return True
                print_status(f"Open eClass {version} is outside the known CVE-2024-26503 range")
                return False

            self.set_info(
                severity="medium",
                cve="CVE-2024-26503",
                reason=(
                    "Open eClass detected but version unknown; CVE-2024-26503 affects "
                    "3.15 — verify before exploitation."
                ),
            )
            return False

        except Exception as e:
            print_error(f"Scanner failed: {e}")
            return False
