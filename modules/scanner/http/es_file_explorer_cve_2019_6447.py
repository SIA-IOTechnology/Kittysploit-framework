#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ast
import json
from typing import Optional, Union

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    DEFAULT_PORT = 59777
    AFFECTED_VERSION = "4.1.9.7.4"
    PROBE_COMMAND = "getDeviceInfo"
    DEVICE_INFO_HINTS = (
        "packagename",
        "versionname",
        "versioncode",
        "product",
        "model",
        "brand",
        "manufacturer",
        "sdk",
        "release",
    )

    __info__ = {
        "name": "ES File Explorer CVE-2019-6447 detection",
        "description": (
            "Detects the unauthenticated ES File Explorer HTTP API on TCP "
            "59777 (CVE-2019-6447). Sends getDeviceInfo and fingerprints "
            "responses from affected builds <= 4.1.9.7.4."
        ),
        "author": ["Nehal Zaman", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2019-6447",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-6447",
        ],
        "modules": [
            "exploits/android/http/es_file_explorer_cve_2019_6447_file_read",
        ],
        "tags": [
            "web",
            "scanner",
            "android",
            "es-file-explorer",
            "file-read",
            "unauthenticated",
            "cve-2019-6447",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 1,
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

    port = OptPort(DEFAULT_PORT, "ES File Explorer HTTP API port", required=True)
    ssl = OptBool(False, "Use HTTPS (the vulnerable service is normally plain HTTP)", required=True)

    def _parse_api_response(self, text: str) -> Optional[Union[dict, list]]:
        if not text or not str(text).strip():
            return None
        body = str(text).strip()
        try:
            return ast.literal_eval(body)
        except (ValueError, SyntaxError):
            pass
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None

    def _probe_api(self) -> Optional[dict]:
        response = self.http_request(
            method="POST",
            path="/",
            data=json.dumps({"command": self.PROBE_COMMAND}),
            headers={"Content-Type": "application/json"},
            timeout=15,
            allow_redirects=False,
        )
        if not response or response.status_code >= 400:
            return None
        data = self._parse_api_response(response.text or "")
        return data if isinstance(data, dict) else None

    def _looks_like_es_api(self, data: dict) -> bool:
        if not data:
            return False
        lowered = {str(key).lower(): value for key, value in data.items()}
        if any(hint in lowered for hint in self.DEVICE_INFO_HINTS):
            return True
        package = str(lowered.get("packagename", "")).lower()
        return "estrongs" in package or "es.file" in package

    def run(self):
        print_status(f"Probing ES File Explorer API on port {self.port}...")
        data = self._probe_api()
        if not data:
            self.set_info(
                severity="info",
                reason=f"No ES File Explorer API response on port {self.port}",
            )
            return False

        if not self._looks_like_es_api(data):
            self.set_info(
                severity="medium",
                reason="HTTP API on 59777 answered getDeviceInfo but fingerprint was inconclusive",
                endpoint="/",
            )
            print_warning("API responded, but device info did not match expected ES markers")
            return True

        version = (
            data.get("versionName")
            or data.get("versionname")
            or data.get("appVersion")
            or data.get("version")
            or ""
        )
        model = data.get("model") or data.get("product") or data.get("brand") or "Android device"
        version_label = f" (version {version})" if version else ""

        self.set_info(
            severity="high",
            cve="CVE-2019-6447",
            reason=(
                f"ES File Explorer HTTP API exposed on port {self.port}{version_label}; "
                f"unauthenticated file read/listing is possible (<= {self.AFFECTED_VERSION})"
            ),
            confidence="high",
            version=str(version),
            endpoint="/",
            service="es-file-explorer",
        )
        print_success(f"ES File Explorer API detected on {model}{version_label}")
        return True
