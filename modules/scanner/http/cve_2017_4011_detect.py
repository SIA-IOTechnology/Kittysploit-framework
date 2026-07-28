#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""McAfee Network Data Loss Prevention User-Agent 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'McAfee Network Data Loss Prevention 9.3.x - Cross-Site Scripting Detection',
        'description': 'McAfee Network Data Loss Prevention User-Agent 9.3.x contains a cross-site scripting vulnerability which allows remote attackers to get session/cookie information via modification of the HTTP request.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'mcafee', 'xss', 'vuln'],
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
            'https://medium.com/@david.valles/cve-2017-4011-reflected-xss-found-in-mcafee-network-data-loss-prevention-ndlp-9-3-x-cf20451870ab',
            'https://kc.mcafee.com/corporate/index?page=content&id=SB10198',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-4011',
            'http://www.securitytracker.com/id/1038523',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2017-4011',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("var ua='Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1';alert(/XSS/);//",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="McAfee Network Data Loss Prevention 9.3.x - Cross-Site Scripting detected",
                path='/',
            )
            return True
        return False

