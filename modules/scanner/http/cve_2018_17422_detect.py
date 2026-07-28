#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dotCMS before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DotCMS < 5.0.2 - Open Redirect Detection',
        'description': 'dotCMS before 5.0.2 contains multiple open redirect vulnerabilities via the html/common/forward_js.jsp FORWARD_URL parameter or the html/portlet/ext/common/page_preview_popup.jsp hostname parameter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'redirect', 'dotcms', 'vuln'],
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
        'references': [
            'https://github.com/dotCMS/core/issues/15286',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-17422',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-17422',
    }

    def run(self):
        for path in ('/html/common/forward_js.jsp?FORWARD_URL=http://oast.me', '/html/portlet/ext/common/page_preview_popup.jsp?hostname=oast.me'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ("self.location = 'http://oast.me'", "location.href = 'http\\x3a\\x2f\\x2fwww\\x2eoast\\x2eme'",)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="DotCMS < 5.0.2 - Open Redirect detected",
                    path=path,
                )
                return True
        return False

