#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GLPI prior 9."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GLPI <9.4.6 - Open Redirect Detection',
        'description': 'GLPI prior 9.4.6 contains an open redirect vulnerability based on a regexp.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'redirect', 'glpi', 'glpi-project', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/glpi-project/glpi/security/advisories/GHSA-gxv6-xq9q-37hg',
            'https://github.com/glpi-project/glpi/archive/9.4.6.zip',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11034',
            'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5WQMONZRWLWOXMHMYWR7A5Q5JJERPMVC/',
            'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/Q4BG2UTINBVV7MTJRXKBQ26GV2UINA6L/',
        ],
        'cve': 'CVE-2020-11034',
    }

    def run(self):
        for path in ('/index.php?redirect=/\\/interact.sh/', '/index.php?redirect=//interact.sh'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_]*\\.)?interact\\.sh(?:\\s*?)$',)
            if (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='medium',
                    reason="GLPI <9.4.6 - Open Redirect detected",
                    path=path,
                )
                return True
        return False

