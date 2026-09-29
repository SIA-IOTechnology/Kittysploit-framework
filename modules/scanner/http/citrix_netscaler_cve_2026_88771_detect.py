#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Citrix NetScaler CVE-2026-88771 pre-auth command injection surface."""

import re
import ssl
import urllib.parse

from requests.adapters import HTTPAdapter

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Citrix NetScaler CVE-2026-88771 Detect",
        "description": (
            "Detects Citrix NetScaler ADC/Gateway instances likely affected by "
            "CVE-2026-88771. Confirms NetScaler presence, parses appliance build "
            "when exposed, and checks whether the AAA login path accepts the "
            "pitboss/PPE log trigger pattern used by ns_monuploadd_err.pl."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-88771"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-88771",
            "https://labs.watchtowr.com/oh-look-the-foot-gun-went-off-again-citrix-netscaler-preauth-command-injection-cve-2026-88771/",
            "https://support.citrix.com/s/article/CTX697096",
        ],
        "tags": [
            "web",
            "scanner",
            "citrix",
            "netscaler",
            "adc",
            "gateway",
            "command-injection",
            "pre-auth",
            "cve-2026-88771",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["citrix", "netscaler", "adc"],
                "endpoint_pattern_any": ["/vpn/", "/logon/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "risk_signal", "from_detail": "pitboss log injection"},
                ],
                "suggested_followups": [
                    "scanner/http/netscaler_gateway_detect",
                    "scanner/http/citrix_netscaler_cve_2026_8451",
                ],
            },
        },
    }

    login_path = OptString("/logon/LogonPoint/index.html", "AAA login page path", False, advanced=True)
    build_paths = OptString(
        "/vpn/index.html,/logon/LogonPoint/receiver.css",
        "Comma-separated paths that may expose build strings",
        False,
        advanced=True,
    )

    _BUILD_RE = re.compile(
        r"(?:NS(?:13|14)\.\d[-\w.]+|NetScaler\s+\d{2}\.\d[-\w.]*)",
        re.IGNORECASE,
    )
    _PITBOSS_TRIGGER = (
        "pitboss PPE unexpectedly died NSPPE-01 missed too many heartbeats"
    )

    def _configure_netscaler_ssl(self):
        class _NetscalerSSLAdapter(HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                ctx = ssl.create_default_context()
                ctx.set_ciphers("DEFAULT@SECLEVEL=1")
                ctx.check_hostname = False
                kwargs["ssl_context"] = ctx
                return super().init_poolmanager(*args, **kwargs)

        self.session.mount("https://", _NetscalerSSLAdapter())

    @staticmethod
    def _parse_build(text: str) -> str:
        match = Module._BUILD_RE.search(text or "")
        return match.group(0) if match else ""

    @staticmethod
    def _build_affected(build: str) -> bool | None:
        if not build:
            return None
        normalized = build.upper().replace("NETSCALER", "").strip()
        match = re.search(r"(13|14)\.(\d+)[-\s]?([\d.]+)?", normalized)
        if not match:
            return None
        major = int(match.group(1))
        minor = int(match.group(2))
        if major == 14 and minor == 1:
            patch = match.group(3) or "0"
            try:
                hotfix = float(patch.split("-")[0])
            except ValueError:
                hotfix = 0.0
            return hotfix < 73.32
        if major == 13 and minor == 1:
            patch = match.group(3) or "0"
            try:
                hotfix = float(patch.split("-")[0])
            except ValueError:
                hotfix = 0.0
            return hotfix < 63.21
        return None

    def _netscaler_present(self) -> tuple[bool, str]:
        for path in ("/vpn/index.html", str(self.login_path or "/logon/LogonPoint/index.html")):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            body = response.text or ""
            headers = " ".join(f"{k}:{v}" for k, v in (response.headers or {}).items())
            blob = f"{body}\n{headers}".lower()
            if any(token in blob for token in ("netscaler", "citrix", "nsc_", "cvpn")):
                return True, body
        return False, ""

    def _probe_login_trigger(self) -> bool:
        login = str(self.login_path or "/logon/LogonPoint/index.html")
        query = urllib.parse.urlencode(
            {
                "login": self._PITBOSS_TRIGGER,
                "passwd": "x",
                "savecredentials": "false",
                "nsg-x1-logon-button": "Log On",
            }
        )
        path = f"{login}?{query}"
        response = self.http_request(method="GET", path=path, allow_redirects=False)
        if not response:
            return False
        return int(response.status_code or 0) in (200, 302, 401, 403)

    def run(self):
        try:
            self._configure_netscaler_ssl()
        except Exception:
            pass

        present, body = self._netscaler_present()
        if not present:
            return False

        build = self._parse_build(body)
        for extra in str(self.build_paths or "").split(","):
            extra = extra.strip()
            if not extra:
                continue
            response = self.http_request(method="GET", path=extra, allow_redirects=False)
            build = build or self._parse_build((response.text or "") if response else "")

        affected = self._build_affected(build)
        trigger_ok = self._probe_login_trigger()
        if affected is False:
            return False
        if affected is True or (trigger_ok and build):
            self.set_info(
                severity="critical",
                cve="CVE-2026-88771",
                reason=(
                    "NetScaler build appears pre-CTX697096 and accepts pitboss/PPE login trigger"
                    if build
                    else "NetScaler gateway accepts pitboss/PPE login trigger pattern"
                ),
                build=build or "unknown",
            )
            return True
        if trigger_ok:
            self.set_info(
                severity="high",
                cve="CVE-2026-88771",
                reason="NetScaler gateway accepts pitboss/PPE log trigger (build unknown)",
                build=build or "unknown",
            )
            return True
        return False
