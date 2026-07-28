#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress WPQA plugin before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress WPQA <5.5 - Improper Access Control Detection',
        'description': 'WordPress WPQA plugin before 5.5 is susceptible to improper access control. The plugin lacks authentication in a REST API endpoint. An attacker can potentially discover private questions sent between users on the site.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp-plugin', 'wpqa', 'idor', 'wpscan', '2code', 'vuln'],
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
            'https://wpscan.com/vulnerability/0416ae2f-5670-4080-a88d-3484bb19d8c8',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1598',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1598',
            'https://github.com/20142995/Goby',
            'https://github.com/WhooAmii/POC_to_review',
        ],
        'cve': 'CVE-2022-1598',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/wp/v2/asked-question', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"id":', '"rendered":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress WPQA <5.5 - Improper Access Control detected",
                path='/wp-json/wp/v2/asked-question',
            )
            return True
        return False

