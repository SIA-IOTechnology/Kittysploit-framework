#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_probe import run_nextjs_version_scan


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js /_next/image OOM (GHSA-h64f) detection",
        "description": (
            "Fingerprints Next.js and flags versions < 16.2.5 potentially affected by "
            "GHSA-h64f-5h5j-jqjh (/_next/image OOM)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "advisory": "GHSA-h64f-5h5j-jqjh",
        "references": ["https://github.com/advisories/GHSA-h64f-5h5j-jqjh"],
        "tags": ["scanner", "http", "nextjs", "dos", "image", "oom", "ghsa-h64f"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.2,
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
        return run_nextjs_version_scan(
            self,
            advisory="GHSA-h64f-5h5j-jqjh",
            patched_version="16.2.5",
            issue_label="GHSA-h64f /_next/image OOM",
            severity="high",
        )
