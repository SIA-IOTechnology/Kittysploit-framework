#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft FrontPage Server Extensions configuration files were accessible, exposing version details, directory."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft FrontPage Configuration - Exposure Detection',
        'description': 'Microsoft FrontPage Server Extensions configuration files were accessible, exposing version details, directory paths, and other configurations. This was a common misconfiguration on old (2000s) IIS servers with FrontPage Server Extensions installed.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'exposure', 'frontpage', 'microsoft', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://docs.microsoft.com/en-us/archive/blogs/fabdulwahab/security-protecting-sharepoint-server-applications',
            'https://www.tenable.com/plugins/was/112772',
            'https://stackoverflow.com/questions/1163820/what-are-vti-cnf-vti-pvt-vti-script-and-vti-txt-folders',
        ],
    }

    def run(self):
        for path in ('/_vti_inf.html', '/_vti_pvt/service.cnf', '/_vti_pvt/access.cnf', '/_vti_txt/default.wti/All.cat'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('vti_extenderversion:', 'FPVersion=', 'PasswordDir:', 'Catalog for database:',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='low',
                    reason="Microsoft FrontPage Configuration - Exposure detected",
                    path=path,
                )
                return True
        return False

