#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Eclipse Jetty server has directory listing enabled, which exposes the directory structure and file names to un."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Eclipse Jetty - Directory Listing Enabled Detection',
        'description': 'Eclipse Jetty server has directory listing enabled, which exposes the directory structure and file names to unauthenticated users. This can reveal sensitive files, backup files, configuration files, and aid attackers in reconnaissance.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'jetty', 'misconfig', 'exposure', 'listing', 'eclipse'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
            'https://www.eclipse.org/jetty/documentation/jetty-11/operations-guide/index.html',
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
            'https://cwe.mitre.org/data/definitions/548.html',
        ],
    }

    def run(self):
        for path in ('/', '/static/', '/resources/', '/assets/', '/files/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Directory listing for', 'Index of /', '[To Parent Directory]', 'Directory: /',)
            body_all = ('Jetty', 'jetty-dir.css',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="Eclipse Jetty - Directory Listing Enabled detected",
                    path=path,
                )
                return True
        return False

