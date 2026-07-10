#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Flask Debug Mode detection',
        'description': 'Detects if Flask debug mode (Werkzeug) is enabled on the target, which may lead to RCE.',
        'author': 'KittySploit Team',
        'severity': 'high',
        'modules': ['exploits/http/flask_debug_rce'],
        'tags': ['web', 'scanner', 'flask', 'werkzeug', 'debug', 'rce'],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
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
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        try:
            # Check for Werkzeug console
            response = self.http_request(method="GET", path="/console", allow_redirects=False)
            if response and response.status_code == 200:
                if 'werkzeug' in response.text.lower() or 'console' in response.text.lower():
                    self.set_info(severity="high", reason="Flask Werkzeug debug console detected")
                    return True
            
            # Check for debug error page
            response = self.http_request(method="GET", path="/nonexistent-page-for-flask-check", allow_redirects=False)
            if response:
                content = response.text.lower()
                if 'werkzeug' in content and 'debug' in content:
                    self.set_info(severity="high", reason="Flask Werkzeug debug mode enabled")
                    return True
            
            return False
        except Exception:
            return False
