#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""b2evolution CMS before 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'b2evolution CMS <6.11.6 - Open Redirect Detection',
        'description': 'b2evolution CMS before 6.11.6 contains an open redirect vulnerability via the redirect_to parameter in email_passthrough.php. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'packetstorm', 'edb', 'redirect', 'b2evolution', 'vuln'],
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
            'https://github.com/b2evolution/b2evolution/issues/102',
            'http://packetstormsecurity.com/files/161362/b2evolution-CMS-6.11.6-Open-Redirection.html',
            'https://www.exploit-db.com/exploits/49554',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-22840',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-22840',
    }

    def run(self):
        r = self.http_request(method="GET", path='/email_passthrough.php?email_ID=1&type=link&email_key=5QImTaEHxmAzNYyYvENAtYHsFu7fyotR&redirect_to=http%3A%2F%2Finteract.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_]*\\.)?interact\\.sh(?:\\s*?)$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="b2evolution CMS <6.11.6 - Open Redirect detected",
                path='/email_passthrough.php?email_ID=1&type=link&email_key=5QImTaEHxmAzNYyYvENAtYHsFu7fyotR&redirect_to=http%3A%2F%2Finteract.sh',
            )
            return True
        return False

