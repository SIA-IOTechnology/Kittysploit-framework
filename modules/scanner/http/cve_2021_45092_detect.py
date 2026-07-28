#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability exists in Thinfinity VirtualUI in a function located in /lab."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Thinfinity Iframe Injection Detection',
        'description': 'A vulnerability exists in Thinfinity VirtualUI in a function located in /lab.html reachable which by default could allow IFRAME injection via the "vpath" parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'packetstorm', 'iframe', 'thinfinity', 'tenable', 'injection', 'cybelesoft', 'vkev', 'vuln'],
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
            'https://github.com/cybelesoft/virtualui/issues/2',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-44848',
            'https://www.tenable.com/cve/CVE-2021-45092',
            'http://packetstormsecurity.com/files/166068/Thinfinity-VirtualUI-2.5.41.0-IFRAME-Injection.html',
            'https://github.com/danielmofer/nuclei_templates',
        ],
        'cve': 'CVE-2021-45092',
    }

    def run(self):
        r = self.http_request(method="GET", path='/lab.html?vpath=//interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('.*vpath.*', 'thinfinity',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Thinfinity Iframe Injection detected",
                path='/lab.html?vpath=//interact.sh',
            )
            return True
        return False

