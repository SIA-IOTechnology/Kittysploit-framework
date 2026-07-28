#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zoho ManageEngine ServiceDesk Plus before 11306, ServiceDesk Plus MSP before 10530, and SupportCenter Plus bef."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zoho ManageEngine ServiceDesk Plus - Remote Code Execution Detection',
        'description': 'Zoho ManageEngine ServiceDesk Plus before 11306, ServiceDesk Plus MSP before 10530, and SupportCenter Plus before 11014 are vulnerable to unauthenticated remote code execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'rce', 'kev', 'msf', 'zoho', 'manageengine', 'zohocorp', 'vkev', 'vuln'],
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
            'https://www.cisa.gov/uscert/ncas/alerts/aa21-336a',
            'https://unit42.paloaltonetworks.com/tiltedtemple-manageengine-servicedesk-plus/',
            'https://github.com/horizon3ai/CVE-2021-44077',
            'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/http/manageengine_servicedesk_plus_cve_2021_44077.rb',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-44077',
        ],
        'cve': 'CVE-2021-44077',
    }

    def run(self):
        r = self.http_request(method="GET", path='/RestAPI/ImportTechnicians', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<form name="ImportTechnicians"',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Zoho ManageEngine ServiceDesk Plus - Remote Code Execution detected",
                path='/RestAPI/ImportTechnicians',
            )
            return True
        return False

