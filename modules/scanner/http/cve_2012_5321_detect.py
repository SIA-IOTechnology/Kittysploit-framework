#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tiki-featured_link."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TikiWiki CMS Groupware v8.3 - Open Redirect Detection',
        'description': 'tiki-featured_link.php in TikiWiki CMS/Groupware 8.3 allows remote attackers to load arbitrary web site pages into frames and conduct phishing attacks via the url parameter, aka "frame injection',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'redirect', 'tikiwiki', 'groupware', 'tiki', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2012-5321',
            'https://www.exploit-db.com/exploits/36848',
            'http://st2tea.blogspot.com/2012/02/tiki-wiki-cms-groupware-frame-injection.html',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/73403',
        ],
        'cve': 'CVE-2012-5321',
    }

    def run(self):
        r = self.http_request(method="GET", path='/tiki-featured_link.php?type=f&url=https://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="TikiWiki CMS Groupware v8.3 - Open Redirect detected",
                path='/tiki-featured_link.php?type=f&url=https://interact.sh',
            )
            return True
        return False

