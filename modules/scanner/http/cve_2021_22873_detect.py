#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Revive Adserver before 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Revive Adserver <5.1.0 - Open Redirect Detection',
        'description': 'Revive Adserver before 5.1.0 contains an open redirect vulnerability via the dest, oadest, and ct0 parameters of the lg.php and ck.php delivery scripts. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'hackerone', 'seclists', 'packetstorm', 'redirect', 'revive', 'revive-adserver', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
            'https://hackerone.com/reports/1081406',
            'https://github.com/revive-adserver/revive-adserver/issues/1068',
            'http://seclists.org/fulldisclosure/2021/Jan/60',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-22873',
            'http://packetstormsecurity.com/files/161070/Revive-Adserver-5.0.5-Cross-Site-Scripting-Open-Redirect.html',
        ],
        'cve': 'CVE-2021-22873',
    }

    def run(self):
        for path in ('/ads/www/delivery/lg.php?dest=http://interact.sh', '/adserve/www/delivery/lg.php?dest=http://interact.sh', '/adserver/www/delivery/lg.php?dest=http://interact.sh', '/openx/www/delivery/lg.php?dest=http://interact.sh', '/revive/www/delivery/lg.php?dest=http://interact.sh', '/www/delivery/lg.php?dest=http://interact.sh'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
            if (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Revive Adserver <5.1.0 - Open Redirect detected",
                    path=path,
                )
                return True
        return False

