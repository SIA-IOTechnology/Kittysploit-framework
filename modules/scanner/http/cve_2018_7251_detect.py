#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Anchor CMS 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Anchor CMS 0.12.3 - Error Log Exposure Detection',
        'description': 'Anchor CMS 0.12.3 is susceptible to an error log exposure vulnerability due to an issue in config/error.php. The error log is exposed at an errors.log URI, and contains MySQL credentials if a MySQL error (such as "Too many connections") has occurred.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'anchorcms', 'logs', 'error', 'packetstorm', 'vuln'],
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
            'https://github.com/anchorcms/anchor-cms/issues/1247',
            'https://twitter.com/finnwea/status/965279233030393856',
            'http://packetstormsecurity.com/files/154723/Anchor-CMS-0.12.3a-Information-Disclosure.html',
            'https://github.com/anchorcms/anchor-cms/releases/tag/0.12.7',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-7251',
        ],
        'cve': 'CVE-2018-7251',
    }

    def run(self):
        r = self.http_request(method="GET", path='/anchor/errors.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"date":', '"message":', '"trace":[',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Anchor CMS 0.12.3 - Error Log Exposure detected",
                path='/anchor/errors.log',
            )
            return True
        return False

