#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection dépôt Git exposé."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = [
    "/.git/HEAD",
    "/.git/config",
]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Exposed Git repository detection",
        "description": "Detects publicly accessible Git metadata such as /.git/HEAD or /.git/config.",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["web", "scanner", "git", "disclosure", "source-code"],
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

    def run(self):
        for path in PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue

            body = (r.text or "").strip()
            if path.endswith("/HEAD") and "ref: refs/" in body:
                self.set_info(severity="medium", reason=f"Exposed Git metadata at {path}")
                return True
            if path.endswith("/config") and "[core]" in body:
                self.set_info(severity="medium", reason=f"Exposed Git config at {path}")
                return True

        return False
