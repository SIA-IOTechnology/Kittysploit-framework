#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Langflow CSV Agent RCE detection",
        "description": (
            "Detects Langflow instances affected by CVE-2026-27966 by checking version "
            "(< 1.8.0) and optionally validating API key access."
        ),
        "author": "KittySploit Team",
        "severity": "critical",
        "cve": "CVE-2026-27966",
        "references": [
            "https://github.com/advisories/GHSA-3645-fxcv-hqr4",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27966",
        ],
        "modules": [
            "exploits/multi/http/langflow_rce_cve_2026_27966",
        ],
        "tags": [
            "web",
            "scanner",
            "langflow",
            "rce",
            "cve-2026-27966",
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
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    path = OptString("/", "Base path where Langflow is exposed", required=False)
    apikey = OptString("", "Langflow API key (optional, improves confidence)", required=False)

    @staticmethod
    def _version_lt(v1: str, v2: str) -> bool:
        def norm(v):
            out = []
            for token in str(v).split("."):
                digits = "".join(ch for ch in token if ch.isdigit())
                out.append(int(digits) if digits else 0)
            while len(out) < 3:
                out.append(0)
            return tuple(out[:3])

        return norm(v1) < norm(v2)

    def _api_path(self, suffix: str) -> str:
        base = str(self.path or "/").strip() or "/"
        if not base.startswith("/"):
            base = f"/{base}"
        if base.endswith("/"):
            base = base[:-1]
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return suffix if base == "" else f"{base}{suffix}"

    def run(self):
        try:
            version_resp = self.http_request(
                method="GET",
                path=self._api_path("/api/v1/version"),
                allow_redirects=True,
                timeout=15,
            )
            if not version_resp or version_resp.status_code != 200:
                return False

            try:
                version_doc = version_resp.json()
            except Exception:
                return False

            version = str(version_doc.get("version", "")).strip()
            if not version:
                return False

            if not self._version_lt(version, "1.8.0"):
                return False

            if self.apikey:
                whoami = self.http_request(
                    method="GET",
                    path=self._api_path("/api/v1/users/whoami"),
                    headers={"x-api-key": self.apikey},
                    allow_redirects=False,
                    timeout=15,
                )
                if whoami and whoami.status_code == 200:
                    self.set_info(
                        severity="critical",
                        cve="CVE-2026-27966",
                        reason=f"Langflow {version} (< 1.8.0) with valid API key",
                    )
                    return True

                self.set_info(
                    severity="medium",
                    cve="CVE-2026-27966",
                    reason=f"Langflow {version} (< 1.8.0) detected but API key validation failed",
                )
                return True

            self.set_info(
                severity="medium",
                cve="CVE-2026-27966",
                reason=f"Langflow {version} (< 1.8.0) detected; provide APIKEY for higher confidence",
            )
            return True
        except Exception:
            return False
