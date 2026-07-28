#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IBM Cloud Object Storage bucket is publicly accessible, potentially exposing sensitive files and data."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IBM Cloud Object Storage - Bucket Exposure Detection',
        'description': 'IBM Cloud Object Storage bucket is publicly accessible, potentially exposing sensitive files and data. Public bucket listing allows enumeration of stored objects.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'ibm', 'cloud', 'bucket', 'exposure', 'misconfig', 's3'],
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
            'https://cloud.ibm.com/docs/cloud-object-storage',
            'https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-iam-bucket-permissions',
        ],
    }

    def run(self):
        for path in ('/', '/?list-type=2'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
            body_any = ('application/xml', 'text/xml',)
            body_all = ('<listbucketresult', '<name>',)
            header_any = ('ibm-sse-kp-enabled', 'ibm-sse-kp-customer-root-key-crn', 'ibm-',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='info',
                    reason="IBM Cloud Object Storage - Bucket Exposure detected",
                    path=path,
                )
                return True
        return False

