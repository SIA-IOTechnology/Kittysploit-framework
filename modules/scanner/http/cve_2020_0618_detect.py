#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft SQL Server Reporting Services is vulnerable to a remote code execution vulnerability because it inco."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft SQL Server Reporting Services - Remote Code Execution Detection',
        'description': 'Microsoft SQL Server Reporting Services is vulnerable to a remote code execution vulnerability because it incorrectly handles page requests.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rce', 'packetstorm', 'microsoft', 'kev', 'vkev', 'vuln'],
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
            'https://www.mdsec.co.uk/2020/02/cve-2020-0618-rce-in-sql-server-reporting-services-ssrs/',
            'https://github.com/euphrat1ca/CVE-2020-0618',
            'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0618',
            'http://packetstormsecurity.com/files/156707/SQL-Server-Reporting-Services-SSRS-ViewState-Deserialization.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-0618',
        ],
        'cve': 'CVE-2020-0618',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ReportServer/Pages/ReportViewer.aspx', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('value="View Report"',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Microsoft SQL Server Reporting Services - Remote Code Execution detected",
                path='/ReportServer/Pages/ReportViewer.aspx',
            )
            return True
        return False

