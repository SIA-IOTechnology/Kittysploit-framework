#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenAM contains an LDAP injection vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LDAP Injection In OpenAM Detection',
        'description': "OpenAM contains an LDAP injection vulnerability. When a user tries to reset his password, they are asked to enter username, and then the backend validates whether the user exists or not through an LDAP query. If the user exists, the password reset token is sent to the user's email. Enumeration can allow for full password retrieval.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'openam', 'ldap', 'injection', 'forgerock', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://github.com/sullo/advisory-archives/blob/master/Forgerock_OpenAM_LDAP_injection.md https://hackerone.com/reports/1278050 https://www.guidepointsecurity.com/blog/ldap-injection-in-forgerock-openam-exploiting-cve-2021-29156/ https://portswigger.net/research/hidden-oauth-attack-vectors',
            'https://portswigger.net/research/hidden-oauth-attack-vectors',
            'https://bugster.forgerock.org/jira/browse/OPENAM-10135',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-29156',
    }

    def run(self):
        for path in ('/openam/ui/PWResetUserValidation', '/OpenAM-11.0.0/ui/PWResetUserValidation', '/ui/PWResetUserValidation'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('jato.pageSession',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="LDAP Injection In OpenAM detected",
                    path=path,
                )
                return True
        return False

