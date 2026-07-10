#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection fichiers .env exposés."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/app/.env",
    "/config/.env",
]

KEYWORDS = [
    "app_key=",
    "app_env=",
    "db_password=",
    "db_username=",
    "aws_access_key_id=",
    "mail_host=",
    "secret_key=",
]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Exposed .env file detection",
        "description": "Detects publicly accessible .env files containing application secrets or environment configuration.",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["web", "scanner", "env", "secrets", "disclosure", "config"],
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

            body = (r.text or "").lower()
            if any(keyword in body for keyword in KEYWORDS):
                self.set_info(severity="high", reason=f"Exposed environment file at {path}")
                return True

        return False
