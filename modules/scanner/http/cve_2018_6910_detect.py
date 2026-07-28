#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DedeCMS 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DedeCMS 5.7 - Path Disclosure Detection',
        'description': 'DedeCMS 5.7 allows remote attackers to discover the full path via a direct request for include/downmix.inc.php or inc/inc_archives_functions.php',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'dedecms', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2018-6910',
            'https://github.com/kongxin520/DedeCMS/blob/master/DedeCMS_5.7_Bug.md',
            'https://kongxin.gitbook.io/dedecms-5-7-bug/',
            'https://github.com/zhibx/fscan-Intranet',
            'https://github.com/0ps/pocassistdb',
        ],
        'cve': 'CVE-2018-6910',
    }

    def run(self):
        r = self.http_request(method="GET", path='/include/downmix.inc.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('downmix.inc.php', 'Call to undefined function helper()',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="DedeCMS 5.7 - Path Disclosure detected",
                path='/include/downmix.inc.php',
            )
            return True
        return False

