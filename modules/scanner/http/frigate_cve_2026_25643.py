#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response, looks_like_html, parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Frigate NVR RCE detection (CVE-2026-25643)",
        "description": (
            "Detects CVE-2026-25643 by fingerprinting Frigate NVR and checking whether the "
            "reported version is <= 0.16.3. Optionally confirms an unauthenticated exploit "
            "path when /api/config/raw is reachable without credentials."
        ),
        "author": ["joshuavanderpoll", "jduardo2704", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-25643",
        "references": [
            "https://github.com/jduardo2704/CVE-2026-25643-Frigate-RCE",
            "https://github.com/blakeblackshear/frigate/security/advisories/GHSA-4c97-5jmr-8f6x",
        ],
        "modules": [
            "exploits/multi/http/frigate_cve_2026_25643_rce",
        ],
        "tags": ["web", "scanner", "frigate", "nvr", "go2rtc", "config-injection", "rce"],
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

    base_path = OptString("/", "Frigate base path", required=False)
    port = OptPort(5000, "Target port", required=True)
    ssl = OptBool(False, "Use HTTPS", required=True)
    username = OptString("", "Frigate username (optional, improves config probe)", required=False)
    password = OptString("", "Frigate password (optional)", required=False)
    check_config_access = OptBool(
        True,
        "Probe /api/config/raw to confirm unauthenticated admin access",
        required=False,
        advanced=True,
    )

    def _prefix(self) -> str:
        base = str(self.base_path or "/").strip() or "/"
        if not base.startswith("/"):
            base = "/" + base
        return base.rstrip("/")

    def _api_path(self, suffix: str) -> str:
        prefix = self._prefix()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{prefix}{suffix}" if prefix else suffix

    @staticmethod
    def _version_gte(v1: str, v2: str) -> bool:
        def norm(v: str):
            out = []
            for token in str(v).split("."):
                digits = "".join(ch for ch in token if ch.isdigit())
                out.append(int(digits) if digits else 0)
            while len(out) < 3:
                out.append(0)
            return tuple(out[:3])

        return norm(v1) >= norm(v2)

    def _login(self) -> bool:
        user = str(self.username or "").strip()
        pwd = str(self.password or "")
        if not user or not pwd:
            return False

        response = self.http_request(
            method="POST",
            path=self._api_path("/api/login"),
            json={"user": user, "password": pwd},
            timeout=max(int(self.timeout or 12), 12),
        )
        return bool(response and response.status_code == 200)

    def _fetch_version(self) -> str:
        response = self.http_request(
            method="GET",
            path=self._api_path("/api/version"),
            timeout=max(int(self.timeout or 12), 12),
        )
        if not response or response.status_code != 200:
            return ""

        try:
            data = response.json()
        except Exception:
            if is_html_response(response):
                return ""
            return ""

        if isinstance(data, dict):
            return str(data.get("version") or data.get("frigate") or "").strip()
        return str(data).strip()

    @staticmethod
    def _looks_like_frigate(body: str) -> bool:
        if not body or looks_like_html(body):
            return False
        text = body.lower()
        return "frigate" in text or "go2rtc" in text

    @staticmethod
    def _looks_like_frigate_config(content: str) -> bool:
        if not content or looks_like_html(content):
            return False
        text = str(content).strip()
        if text.startswith('"') and text.endswith('"'):
            try:
                text = json.loads(text)
            except json.JSONDecodeError:
                pass
        blob = str(text).lower()
        markers = ("mqtt:", "cameras:", "detectors:", "ffmpeg:", "birdseye:", '"mqtt"', '"cameras"')
        return sum(1 for marker in markers if marker in blob) >= 2

    def _fingerprint_frigate(self) -> bool:
        version = self._fetch_version()
        if version:
            return True

        response = self.http_request(
            method="GET",
            path=self._prefix() or "/",
            timeout=max(int(self.timeout or 10), 10),
            allow_redirects=True,
        )
        if not response:
            return False
        return self._looks_like_frigate(response.text or "")

    def _config_readable(self) -> bool:
        response = self.http_request(
            method="GET",
            path=self._api_path("/api/config/raw"),
            timeout=max(int(self.timeout or 12), 12),
        )
        if not response or response.status_code != 200:
            return False

        content = (response.text or "").strip()
        if not content or is_html_response(response, content):
            return False

        if content.startswith('"') and content.endswith('"'):
            try:
                content = json.loads(content)
            except json.JSONDecodeError:
                pass

        return self._looks_like_frigate_config(str(content))

    def check(self):
        is_frigate = self._fingerprint_frigate()
        version = self._fetch_version()

        if version and self._version_gte(version, "0.16.4"):
            return {
                "vulnerable": False,
                "reason": f"Frigate {version} appears patched (>= 0.16.4)",
                "confidence": "high",
                "version": version,
                "unauth_config": False,
            }

        if not is_frigate:
            return {
                "vulnerable": False,
                "reason": "Target does not look like Frigate NVR",
                "confidence": "low",
                "version": version,
                "unauth_config": False,
            }

        unauth_config = False
        if self.check_config_access:
            unauth_config = self._config_readable()

        if self.username and self.password:
            self._login()

        if version and not self._version_gte(version, "0.16.4"):
            if unauth_config:
                return {
                    "vulnerable": True,
                    "reason": (
                        f"Frigate {version} (<= 0.16.3) with readable /api/config/raw "
                        "(unauthenticated admin access)"
                    ),
                    "confidence": "high",
                    "version": version,
                    "unauth_config": True,
                }
            return {
                "vulnerable": True,
                "reason": (
                    f"Frigate {version} matches vulnerable range (<= 0.16.3); "
                    "exploit requires admin credentials unless auth is disabled"
                ),
                "confidence": "medium",
                "version": version,
                "unauth_config": False,
            }

        if unauth_config:
            return {
                "vulnerable": True,
                "reason": "Frigate detected with unauthenticated /api/config/raw access",
                "confidence": "high",
                "version": version,
                "unauth_config": True,
            }

        return {
            "vulnerable": False,
            "reason": "Frigate-like target detected but version unknown and config not readable without auth",
            "confidence": "low",
            "version": version,
            "unauth_config": False,
        }

    def run(self):
        try:
            result = self.check()
            if not result.get("vulnerable"):
                return False

            severity = "critical" if result.get("confidence") == "high" else "high"
            self.set_info(
                severity=severity,
                cve="CVE-2026-25643",
                reason=result.get("reason", "Frigate CVE-2026-25643 exposure detected"),
                confidence=result.get("confidence", "unknown"),
                version=result.get("version", ""),
                unauth_config=bool(result.get("unauth_config")),
            )
            return True
        except Exception:
            return False
