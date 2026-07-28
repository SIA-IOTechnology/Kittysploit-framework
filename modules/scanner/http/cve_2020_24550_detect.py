#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EpiServer Find before 13."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EpiServer Find <13.2.7 - Open Redirect Detection',
        'description': 'EpiServer Find before 13.2.7 contains an open redirect vulnerability via the _t_redirect parameter in a crafted URL, such as a /find_v2/_click URL. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'redirect', 'episerver', 'vuln'],
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
            'https://labs.nettitude.com/blog/cve-2020-24550-open-redirect-in-episerver-find/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-24550',
            'https://github.com/anonymous364872/Rapier_Tool',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2020-24550',
    }

    def run(self):
        r = self.http_request(method="GET", path='/find_v2/_click?_t_id=&_t_q=&_t_hit.id=&_t_redirect=https://interact.sh', allow_redirects=False)
        if not r or r.status_code != 301:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('Location: https://interact.sh',)
        if (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="EpiServer Find <13.2.7 - Open Redirect detected",
                path='/find_v2/_click?_t_id=&_t_q=&_t_hit.id=&_t_redirect=https://interact.sh',
            )
            return True
        return False

