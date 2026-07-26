#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Microsoft Exchange CVE-2026-45504 detection",
        "description": (
            "Detects Microsoft Exchange Server instances exposing OWA and EWS endpoints "
            "used in CVE-2026-45504 (authenticated SSRF arbitrary file read via reference "
            "attachments and GetAttachmentPreview)."
        ),
        "author": ["Batuhan Er (@int20z)", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-45504",
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-45504",
        ],
        "modules": [
            "auxiliary/admin/http/exchange_cve_2026_45504_file_read",
        ],
        "tags": [
            "web",
            "scanner",
            "exchange",
            "owa",
            "ews",
            "ssrf",
            "file-read",
            "microsoft",
            "cve-2026-45504",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 'medium',
        'noise': 'low',
        'value': 'medium',
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(443, "Exchange HTTPS port", required=True)
    ssl = OptBool(True, "Use HTTPS", required=True)

    def _looks_like_exchange(self, response, body: str) -> bool:
        if not response:
            return False
        text = (body or "").lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        return any(
            (
                "outlook" in text,
                "exchange" in text,
                "owalogocontainer" in text,
                "x-owa-version" in headers,
                "x-owa-version" in text,
                "microsoft exchange" in text,
            )
        )

    def _ews_reachable(self) -> bool:
        response = self.http_request(
            method="GET",
            path="/ews/exchange.asmx",
            allow_redirects=False,
            timeout=10,
        )
        if not response:
            return False
        if response.status_code in (200, 401, 403):
            body = (response.text or "").lower()
            auth = str(response.headers.get("WWW-Authenticate", "")).lower()
            return (
                "exchange" in body
                or "wsdl" in body
                or "ntlm" in auth
                or "negotiate" in auth
            )
        return False

    def run(self):
        try:
            owa_response = None
            owa_path = ""
            for path in ("/owa/", "/owa/auth/logon.aspx"):
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=True,
                    timeout=10,
                )
                if not response:
                    continue
                if self._looks_like_exchange(response, response.text or ""):
                    owa_response = response
                    owa_path = path
                    break

            if not owa_response:
                return False

            ews_ok = self._ews_reachable()
            owa_version = (
                owa_response.headers.get("X-OWA-Version")
                or owa_response.headers.get("x-owa-version")
                or ""
            )

            reason = f"Microsoft Exchange OWA detected at {owa_path}"
            if owa_version:
                reason += f" (OWA version: {owa_version})"
            if ews_ok:
                reason += "; EWS endpoint reachable for CVE-2026-45504 chain"
            else:
                reason += "; EWS endpoint not confirmed (authenticated follow-up required)"

            self.set_info(
                severity="high" if ews_ok else "medium",
                cve="CVE-2026-45504",
                reason=reason,
                owa_path=owa_path,
                ews_reachable=ews_ok,
                owa_version=owa_version or None,
            )
            return True
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
