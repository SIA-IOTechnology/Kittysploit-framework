#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import List, Optional, Tuple
from urllib.parse import quote_plus

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    AFFECTED_VERSION = (18, 2, 39)
    LOGIN_PATH = "/public/checklogin.htm"
    LOGIN_PAGE_MARKERS = ("prtg", "checklogin", "prtg network monitor")

    __info__ = {
        "name": "PRTG Network Monitor CVE-2018-9276 detection",
        "description": (
            "Detects PRTG Network Monitor instances below 18.2.39 vulnerable to authenticated "
            "command injection in EXE notification settings (CVE-2018-9276). Fingerprints the "
            "Server header and optionally confirms administrator credentials."
        ),
        "author": ["wildkindcc", "M4LVO", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2018-9276",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-9276",
            "https://www.exploit-db.com/exploits/46527",
        ],
        "modules": [
            "exploits/windows/http/prtg_cve_2018_9276_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "prtg",
            "windows",
            "authenticated",
            "command-injection",
            "rce",
            "cve-2018-9276",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(80, "PRTG web interface port", required=True)
    ssl = OptBool(False, "Use HTTPS for the PRTG web interface", required=True)
    username = OptString("prtgadmin", "Optional PRTG administrator username", required=False)
    password = OptString("prtgadmin", "Optional PRTG administrator password", required=False)

    def _parse_version_parts(self, version: str) -> Optional[List[int]]:
        if not version:
            return None
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
        if not match:
            return None
        return [int(match.group(i)) for i in range(1, 4)]

    def _version_lt(self, parts: List[int], bound: Tuple[int, int, int]) -> bool:
        for left, right in zip(parts, bound):
            if left < right:
                return True
            if left > right:
                return False
        return False

    def _version_vulnerable(self, server_header: str) -> Optional[bool]:
        parts = self._parse_version_parts(server_header)
        if not parts:
            return None
        return self._version_lt(parts, self.AFFECTED_VERSION)

    def _fetch_server_header(self) -> Tuple[Optional[str], Optional[str]]:
        response = self.http_request(method="GET", path="/", timeout=15, allow_redirects=True)
        if not response:
            return None, None
        server = response.headers.get("Server", "")
        body = (response.text or "").lower()
        return server, body

    def _looks_like_prtg(self, server_header: str, body: str) -> bool:
        if server_header and "prtg" in server_header.lower():
            return True
        return any(marker in body for marker in self.LOGIN_PAGE_MARKERS)

    def _try_login(self) -> bool:
        payload = (
            "loginurl=%2Fmyaccount.htm%3Ftabid%3D2"
            f"&username={quote_plus(self.username)}"
            f"&password={quote_plus(self.password)}"
        )
        response = self.http_request(
            method="POST",
            path=self.LOGIN_PATH,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=20,
            allow_redirects=True,
        )
        if not response:
            return False
        if self.session.cookies.get_dict():
            return True
        return bool(response.headers.get("Set-Cookie", ""))

    def run(self):
        server_header, body = self._fetch_server_header()
        if not server_header and not body:
            print_error("Target not reachable")
            return False

        if not self._looks_like_prtg(server_header or "", body or ""):
            self.set_info(
                severity="info",
                reason="Target does not appear to be PRTG Network Monitor",
            )
            return False

        version_label = server_header or "PRTG (version unknown)"
        print_success(f"PRTG instance detected ({version_label})")

        vuln = self._version_vulnerable(server_header or "")
        login_ok = False
        if self.username and self.password:
            print_status(f"Testing administrator login ({self.username})...")
            login_ok = self._try_login()
            if login_ok:
                print_success("Administrator credentials accepted")
            else:
                print_warning("Supplied credentials did not obtain a session")

        bound = ".".join(str(part) for part in self.AFFECTED_VERSION)

        if vuln is True:
            self.set_info(
                severity="critical",
                cve="CVE-2018-9276",
                reason=(
                    f"{version_label} < {bound}; authenticated EXE notification "
                    "command injection (CVE-2018-9276)"
                ),
                confidence="high" if login_ok else "medium",
                version=server_header,
                endpoint=self.LOGIN_PATH,
            )
            print_warning(f"Version appears vulnerable (< {bound})")
            return True

        if vuln is False:
            self.set_info(
                severity="info",
                reason=f"{version_label} appears patched (>= {bound})",
                version=server_header,
            )
            print_info(f"Version appears patched (>= {bound})")
            return False

        if login_ok:
            self.set_info(
                severity="high",
                cve="CVE-2018-9276",
                reason=(
                    "PRTG detected with valid admin session; version unknown but product "
                    "family is affected by CVE-2018-9276 below 18.2.39"
                ),
                confidence="medium",
                endpoint=self.LOGIN_PATH,
            )
            print_warning("Admin login confirmed; version could not be parsed from Server header")
            return True

        self.set_info(
            severity="medium",
            cve="CVE-2018-9276",
            reason=(
                f"PRTG detected ({version_label}); version not confirmed — instances "
                f"< {bound} are affected when admin credentials are available"
            ),
            confidence="low",
            version=server_header,
            endpoint=self.LOGIN_PATH,
        )
        print_info("PRTG detected; supply valid credentials for stronger confirmation")
        return True
