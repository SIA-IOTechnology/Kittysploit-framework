#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MicroStrategy Web 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MicroStrategy Web 10.4 - Information Disclosure Detection',
        'description': 'MicroStrategy Web 10.4 is susceptible to information disclosure. The JVM configuration, CPU architecture, installation folder, and other information are exposed through /MicroStrategyWS/happyaxis.jsp. An attacker can use this vulnerability to learn more about the application environment and thereby possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'packetstorm', 'seclists', 'microstrategy', 'exposure', 'jvm', 'config', 'xss', 'vuln'],
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
            'http://packetstormsecurity.com/files/157068/MicroStrategy-Intelligence-Server-And-Web-10.4-XSS-Disclosure-SSRF-Code-Execution.html',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11450',
            'https://www.redtimmy.com/web-application-hacking/another-ssrf-another-rce-the-microstrategy-case/',
            'https://nvd.nist.gov/vuln/detail/cve-2020-11450',
            'http://seclists.org/fulldisclosure/2020/Apr/1',
        ],
        'cve': 'CVE-2020-11450',
    }

    def run(self):
        r = self.http_request(method="GET", path='/MicroStrategyWS/happyaxis.jsp', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Axis2 Happiness Page', 'Examining webapp configuration', 'Essential Components',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="MicroStrategy Web 10.4 - Information Disclosure detected",
                path='/MicroStrategyWS/happyaxis.jsp',
            )
            return True
        return False

