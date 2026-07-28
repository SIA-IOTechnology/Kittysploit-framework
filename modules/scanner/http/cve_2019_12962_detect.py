#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LiveZilla Server 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LiveZilla Server 8.0.1.0 - Cross-Site Scripting Detection',
        'description': 'LiveZilla Server 8.0.1.0 is vulnerable to reflected cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'xss', 'edb', 'packetstorm', 'livezilla', 'vuln'],
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
            'https://www.exploit-db.com/exploits/49669',
            'https://forums.livezilla.net/index.php?/topic/10984-fg-vd-19-083085087-livezilla-server-are-vulnerable-to-cross-site-scripting-in-admin-panel/',
            'http://packetstormsecurity.com/files/161867/LiveZilla-Server-8.0.1.0-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-12962',
            'https://github.com/anonymous364872/Rapier_Tool',
        ],
        'cve': 'CVE-2019-12962',
    }

    def run(self):
        r = self.http_request(method="GET", path='/mobile/index.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("var detectedLanguage = ';alert(document.domain)//';",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="LiveZilla Server 8.0.1.0 - Cross-Site Scripting detected",
                path='/mobile/index.php',
            )
            return True
        return False

