#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe Coldfusion versions 2016 (update 16 and earlier), 2018 (update 10 and earlier) and 2021."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe ColdFusion - Cross-Site Scripting Detection',
        'description': "Adobe Coldfusion versions 2016 (update 16 and earlier), 2018 (update 10 and earlier) and 2021.0.0.323925 are affected by an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability. An attacker could abuse this vulnerability to execute arbitrary JavaScript code in context of the current user. Exploitation of this issue requires user interaction.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'adobe', 'misc', 'coldfusion', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
            'https://helpx.adobe.com/security/products/coldfusion/apsb21-16.html',
            'https://twitter.com/Daviey/status/1374070630283415558',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21087',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-21087',
    }

    def run(self):
        for path in ('/cf_scripts/scripts/ajax/package/cfajax.js', '/cf-scripts/scripts/ajax/package/cfajax.js', '/CFIDE/scripts/ajax/package/cfajax.js', '/cfide/scripts/ajax/package/cfajax.js', '/CF_SFSD/scripts/ajax/package/cfajax.js', '/cfide-scripts/ajax/package/cfajax.js', '/cfmx/CFIDE/scripts/ajax/package/cfajax.js'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('eval\\(\\"\\(\\"\\+json\\+\\"\\)\\"\\)',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Adobe ColdFusion - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

