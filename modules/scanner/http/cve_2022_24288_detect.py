#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Airflow prior to version 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Airflow OS Command Injection Detection',
        'description': 'Apache Airflow prior to version 2.2.4 is vulnerable to OS command injection attacks because some example DAGs do not properly sanitize user-provided parameters, making them susceptible to OS Command Injection from the web UI.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'airflow', 'rce', 'apache', 'vkev', 'vuln'],
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
            'https://github.com/advisories/GHSA-3v7g-4pg3-7r6j',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-24288',
            'https://lists.apache.org/thread/dbw5ozcmr0h0lhs0yjph7xdc64oht23t',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Hax0rG1rl/my_cve_and_bounty_poc',
        ],
        'cve': 'CVE-2022-24288',
    }

    def run(self):
        for path in ('/admin/airflow/code?root=&dag_id=example_passing_params_via_test_command', '/code?dag_id=example_passing_params_via_test_command'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('foo was passed in via Airflow CLI Test command with value {{ params.foo }}',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Apache Airflow OS Command Injection detected",
                    path=path,
                )
                return True
        return False

