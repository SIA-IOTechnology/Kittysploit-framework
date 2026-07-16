#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed phpMyAdmin setup wizard."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "phpMyAdmin Setup Detection",
        "description": "Detects publicly accessible phpMyAdmin setup/index.php configuration wizard.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "phpmyadmin", "mysql", "misconfig", "panel"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals'],
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        for path in ("/phpmyadmin/setup/", "/phpMyAdmin/setup/index.php", "/pma/setup/"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code not in (200, 401):
                continue
            body = (r.text or "").lower()
            if "phpmyadmin" in body and ("setup" in body or "configuration" in body):
                self.set_info(
                    severity="high",
                    reason="phpMyAdmin setup wizard exposed",
                    path=path,
                )
                return True
        return False
