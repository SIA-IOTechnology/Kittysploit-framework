#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software are suscept."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco Adaptive Security Appliance Software/Cisco Firepower Threat Defense - Directory Traversal Detection',
        'description': 'Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software are susceptible to directory traversal vulnerabilities that could allow an unauthenticated, remote attacker to obtain read and delete access to sensitive files on a targeted system.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'cisco', 'packetstorm', 'vkev', 'vuln'],
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
            'https://twitter.com/aboul3la/status/1286809567989575685',
            'http://packetstormsecurity.com/files/158648/Cisco-Adaptive-Security-Appliance-Software-9.7-Arbitrary-File-Deletion.html',
            'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-3187',
            'https://github.com/Threekiii/Awesome-POC',
        ],
        'cve': 'CVE-2020-3187',
    }

    def run(self):
        r = self.http_request(method="GET", path='/+CSCOE+/session_password.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('webvpn', 'Webvpn',)
        if (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Cisco Adaptive Security Appliance Software/Cisco Firepower Threat Defense - Directory Traversal detected",
                path='/+CSCOE+/session_password.html',
            )
            return True
        return False

