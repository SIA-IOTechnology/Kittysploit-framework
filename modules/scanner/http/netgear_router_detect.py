#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple NETGEAR router models disclose their serial number which can be used to obtain the admin password if ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NETGEAR Routers - Serial Number Disclosure Detection',
        'description': 'Multiple NETGEAR router models disclose their serial number which can be used to obtain the admin password if password recovery is enabled.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'edb', 'netgear', 'exposure', 'iot', 'router', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/47117'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/rootDesc.xml', allow_redirects=False)
        if not r or r.status_code not in (200, 501):
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<serialNumber>', '<deviceType>', '<modelNumber>',)
        header_any = ('text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="NETGEAR Routers - Serial Number Disclosure detected",
                path='/rootDesc.xml',
            )
            return True
        return False

