#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tomcat's credential disclosure leading to Remote Code Execution via WAR upload."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jolokia <= 1.7.1 Information Leakage Detection',
        'description': "Tomcat's credential disclosure leading to Remote Code Execution via WAR upload.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'jolokia', 'tomcat', 'exposure', 'vuln'],
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
            'https://github.com/laluka/jolokia-exploitation-toolkit/blob/main/exploits/info-leak-tomcat-creds.py',
            'https://therealcoiffeur.github.io/c11011',
        ],
    }

    def run(self):
        for path in ('/jolokia/read/Users:database=UserDatabase,type=UserDatabase', '/actuator/jolokia/read/Users:database=UserDatabase,type=UserDatabase'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('"users":[]',)
            body_all = ('"mbean":"Users:database=UserDatabase,type=UserDatabase"', '"users":',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='critical',
                    reason="Jolokia <= 1.7.1 Information Leakage detected",
                    path=path,
                )
                return True
        return False

