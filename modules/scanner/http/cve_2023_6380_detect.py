#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open redirect vulnerability has been found in the Open CMS product affecting versions 14 and 15 of the 'Mercur."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenCms 14 & 15 - Open Redirect Detection',
        'description': "Open redirect vulnerability has been found in the Open CMS product affecting versions 14 and 15 of the 'Mercury' template",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'redirect', 'opencms', 'alkacon', 'vuln'],
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
            'https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-alkacon-software-opencms',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
            'https://github.com/msegoviag/msegoviag',
        ],
        'cve': 'CVE-2023-6380',
    }

    def run(self):
        r = self.http_request(method="GET", path='/system/modules/alkacon.mercury.template.jsondemo/elements/jsonapi.jsp?content&fallbackLocale&locale=en&rows=1&uri=http://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="OpenCms 14 & 15 - Open Redirect detected",
                path='/system/modules/alkacon.mercury.template.jsondemo/elements/jsonapi.jsp?content&fallbackLocale&locale=en&rows=1&uri=http://interact.sh',
            )
            return True
        return False

