#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Joomla detection',
        'description': 'Detects if Joomla is installed on the target.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'joomla', 'cms'],
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
        score = 0

        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False

        body = (r.text or "").lower()
        headers = str(r.headers).lower()

        # Strong indicators on homepage.
        if re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*joomla', body, re.IGNORECASE):
            score += 4
        if "option=com_" in body:
            score += 3
        if "/components/com_" in body or "/media/com_" in body:
            score += 3
        if "joomla!" in body:
            score += 2

        # Weak indicator.
        if "joomla" in body or "joomla" in headers:
            score += 1

        # Validate administrator behavior/content.
        r2 = self.http_request(method="GET", path="/administrator/", allow_redirects=False)
        if r2 and r2.status_code in [200, 301, 302, 403]:
            admin_body = (r2.text or "").lower()
            location = (r2.headers.get("Location", "") or "").lower()
            if (
                "joomla" in admin_body
                or "mod-login-username" in admin_body
                or "task=login" in admin_body
                or "/administrator/index.php" in location
            ):
                score += 4

        return score >= 5
