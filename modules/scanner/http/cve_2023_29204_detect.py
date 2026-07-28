#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki Commons are technical libraries common to several other top level XWiki projects."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki - Open Redirect Detection',
        'description': 'XWiki Commons are technical libraries common to several other top level XWiki projects. It is possible to bypass the existing security measures put in place to avoid open redirect by using a redirect such as `//mydomain.com` (i.e. omitting the `http:`). It was also possible to bypass it when using URL such as `http:/mydomain.com`. The problem has been patched on XWiki 13.10.10, 14.4.4 and 14.8RC1.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xwiki', 'redirect', 'vuln'],
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
            'https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-xwph-x6xj-wggv',
            'https://jira.xwiki.org/browse/XWIKI-10309',
            'https://jira.xwiki.org/browse/XWIKI-19994',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-29204',
        ],
        'cve': 'CVE-2023-29204',
    }

    def run(self):
        for path in ('/bin/login/XWiki/XWikiLogin?xredirect=//www.oast.me', '/bin/login/XWiki/XWikiLogin?xredirect=http:/www.oast.me'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me\\/?(\\/|[^.].*)?$',)
            if (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='medium',
                    reason="XWiki - Open Redirect detected",
                    path=path,
                )
                return True
        return False

