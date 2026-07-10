#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection lecture anonyme d'objet S3 (check-only)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "AWS S3 public object read detect",
        "description": "Checks anonymous read access to a user-provided object path (no exploitation).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [
            "auxiliary/aws/s3_file_download",
            "auxiliary/aws/s3_sensitive_pattern_scan",
            "auxiliary/aws/aws_s3_exposure_path_prioritizer",
        ],
        "tags": ["cloud", "scanner", "aws", "s3", "misconfig", "public"],
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    object_path = OptString("/index.html", "Object path to test (e.g. /backup.sql)", required=False)
    timeout = OptString("5", "HTTP timeout in seconds", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def run(self):
        path = str(self.object_path or "/index.html").strip()
        if not path.startswith("/"):
            path = "/" + path
        timeout_seconds = self._to_int(self.timeout, 5)
        r = self.http_request(method="HEAD", path=path, allow_redirects=False, timeout=timeout_seconds)
        if not r or r.status_code in (400, 405, 501):
            # Fallback minimal GET for servers not handling HEAD.
            r = self.http_request(
                method="GET",
                path=path,
                allow_redirects=False,
                timeout=timeout_seconds,
                headers={"Range": "bytes=0-0"},
            )
        if not r:
            return False
        if r.status_code == 200:
            size = str((r.headers or {}).get("Content-Length", "unknown"))
            self.set_info(severity="high", reason=f"Anonymous S3 object read possible on {path} (content-length={size})")
            return True
        if r.status_code == 206:
            self.set_info(severity="high", reason=f"Anonymous S3 object ranged-read possible on {path}")
            return True
        return False
