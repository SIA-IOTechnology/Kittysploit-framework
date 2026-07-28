#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected JBoss JMX Console was accessible without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JBoss JMX Console - Unauthenticated Access Detection',
        'description': 'Detected JBoss JMX Console was accessible without authentication. The exposed console provided complete access to all MBeans, including MainDeployer, which enabled arbitrary WAR file deployment, leading to remote code execution. Attackers could view the entire MBean tree, deploy malicious applications, and invoke administrative operations without valid credentials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'jboss', 'unauth', 'misconfig'],
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
            'https://developer.jboss.org/wiki/SecureTheJmxConsole',
            'https://www.invicti.com/web-application-vulnerabilities/jboss-jmx-console-unrestricted-access',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/jmx-console/HtmlAdaptor?action=displayMBeans', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('jboss.deployment', 'jboss.system', 'j_security_check', 'j_username', 'j_password',)
        body_all = ('JMX Agent View', 'ObjectName Filter', 'service=MainDeployer',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="JBoss JMX Console - Unauthenticated Access detected",
                path='/jmx-console/HtmlAdaptor?action=displayMBeans',
            )
            return True
        return False

