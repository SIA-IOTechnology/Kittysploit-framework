#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected an exposed Adobe AEM JCR compare functionality that was accessible without proper authorization."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe AEM JCR Compare Exposure Detection',
        'description': 'Detected an exposed Adobe AEM JCR compare functionality that was accessible without proper authorization. This exposure may have allowed attackers to infer repository structure or sensitive content through comparison operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'aem', 'adobe', 'exposure', 'jcr'],
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
            'https://experienceleague.adobe.com/docs/experience-manager-65/administering/security/security-checklist.html',
            'https://medium.com/@vsr061/adobe-experience-manager-security-issues-9b5bd24e0eb0',
        ],
    }

    def run(self):
        for path in ('/jcr:content.json', '/etc/replication/agents.author/publish/jcr:content.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('application/json',)
            body_all = ('jcr:createdBy', 'cq:template',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Adobe AEM JCR Compare Exposure detected",
                    path=path,
                )
                return True
        return False

