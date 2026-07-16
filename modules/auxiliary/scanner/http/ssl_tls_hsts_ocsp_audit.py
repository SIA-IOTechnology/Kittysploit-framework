#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Audit HSTS policy and OCSP stapling for an HTTPS service."""

from __future__ import annotations

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.hsts_ocsp_audit import audit_hsts_from_headers, probe_ocsp_stapling


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "SSL/TLS HSTS and OCSP Audit",
        "description": (
            "Audit HTTP→HTTPS redirects, HSTS policy quality, and OCSP stapling "
            "on the live TLS service."
        ),
        "author": ["KittySploit Team"],
        "tags": ["web", "tls", "ssl", "hsts", "ocsp", "scanner", "misconfig"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 4,
        'reversible': True,
        'approval_required': False,
        'produces': ['risk_signals', 'tech_hints'],
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
        'chain':         {'produces_capabilities': [{'capability': 'endpoints', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    host_header = OptString("", "Override Host header / SNI (defaults to target)", required=False)
    check_ocsp = OptBool(True, "Probe OCSP stapling via openssl when available", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _hostname(self) -> str:
        override = str(self.host_header or "").strip()
        if override:
            return override
        raw = str(self.target or "").strip()
        return re.sub(r"^https?://", "", raw, flags=re.IGNORECASE).split("/")[0].split(":")[0]

    def _http_probe(self, use_ssl: bool):
        old_ssl = getattr(self, "ssl", True)
        old_port = getattr(self, "port", 443)
        try:
            self.ssl = use_ssl
            self.port = 443 if use_ssl else 80
            return self.http_request(method="GET", path="/", allow_redirects=False)
        finally:
            self.ssl = old_ssl
            self.port = old_port

    def run(self):
        host = self._hostname()
        if not host:
            print_error("Target hostname is required")
            return {"error": "missing_target"}

        http_resp = self._http_probe(use_ssl=False)
        https_resp = self._http_probe(use_ssl=True)

        hsts = audit_hsts_from_headers(
            http_status=http_resp.status_code if http_resp else None,
            http_headers=dict(http_resp.headers) if http_resp else {},
            http_location=http_resp.headers.get("Location", "") if http_resp else "",
            https_status=https_resp.status_code if https_resp else None,
            https_headers=dict(https_resp.headers) if https_resp else {},
            host=host,
        )

        ocsp = probe_ocsp_stapling(host, 443, server_name=host) if self.check_ocsp else None

        if hsts.http_redirects_to_https:
            print_success("HTTP redirects to HTTPS")
        else:
            print_warning("HTTP does not redirect to HTTPS")

        if hsts.hsts_present:
            print_info(
                f"HSTS: max-age={hsts.max_age} includeSubDomains={hsts.include_subdomains} "
                f"preload={hsts.preload}"
            )
        else:
            print_warning("HSTS header missing on HTTPS")

        for issue in hsts.issues:
            print_warning(f"[{issue.get('severity')}] {issue.get('description')}")

        if ocsp and ocsp.checked:
            if ocsp.stapling_present is True:
                print_success(f"OCSP stapling present ({ocsp.detail})")
            elif ocsp.stapling_present is False:
                print_warning(ocsp.detail)
            else:
                print_info(ocsp.detail)

        data = {
            "host": host,
            "hsts": {
                "http_redirects_to_https": hsts.http_redirects_to_https,
                "https_available": hsts.https_available,
                "hsts_present": hsts.hsts_present,
                "hsts_header": hsts.hsts_header,
                "max_age": hsts.max_age,
                "include_subdomains": hsts.include_subdomains,
                "preload": hsts.preload,
                "issues": hsts.issues,
            },
            "ocsp": {
                "checked": ocsp.checked if ocsp else False,
                "stapling_present": ocsp.stapling_present if ocsp else None,
                "detail": ocsp.detail if ocsp else "",
                "method": ocsp.method if ocsp else "",
            } if ocsp else {},
        }

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
