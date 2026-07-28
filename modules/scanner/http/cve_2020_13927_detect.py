#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Airflow's Experimental API prior 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Airflow Experimental <1.10.11 - REST API Auth Bypass Detection',
        'description': "Airflow's Experimental API prior 1.10.11 allows all API requests without authentication.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'packetstorm', 'apache', 'airflow', 'unauth', 'auth-bypass', 'kev', 'vkev', 'vuln'],
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
            'https://lists.apache.org/thread.html/r23a81b247aa346ff193670be565b2b8ea4b17ddbc7a35fc099c1aadd%40%3Cdev.airflow.apache.org%3E',
            'http://packetstormsecurity.com/files/162908/Apache-Airflow-1.10.10-Remote-Code-Execution.html',
            'https://airflow.apache.org/docs/1.10.11/security.html#api-authenticatio',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-13927',
            'http://packetstormsecurity.com/files/174764/Apache-Airflow-1.10.10-Remote-Code-Execution.html',
        ],
        'cve': 'CVE-2020-13927',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/experimental/latest_runs', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"dag_run_url":', '"dag_id":', '"items":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Airflow Experimental <1.10.11 - REST API Auth Bypass detected",
                path='/api/experimental/latest_runs',
            )
            return True
        return False

