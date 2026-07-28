#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe AEM ACS Common pages exposed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe AEM ACS Common Exposure Detection',
        'description': 'Adobe AEM ACS Common pages exposed.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'aem', 'adobe', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/aem2.txt',
        ],
    }

    def run(self):
        for path in ('/etc/acs-commons/jcr-compare.html', '/etc/acs-commons/workflow-remover.html', '/etc/acs-commons/version-compare.html', '/etc/acs-commons/oak-index-manager.html'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<title>Version Compare | ACS AEM Commons</title>', '<title>Oak Index Manager | ACS AEM Commons</title>', '<title>JCR Compare | ACS AEM Commons</title>', '<title>Workflow Remover | ACS AEM Commons</title>',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="Adobe AEM ACS Common Exposure detected",
                    path=path,
                )
                return True
        return False

