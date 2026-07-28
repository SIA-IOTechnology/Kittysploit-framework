#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KubeView through 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KubeView <=0.1.31 - Information Disclosure Detection',
        'description': 'KubeView through 0.1.31 is susceptible to information disclosure. An attacker can obtain control of a Kubernetes cluster because api/scrape/kube-system does not require authentication and retrieves certificate files that can be used for authentication as kube-admin. An attacker can thereby possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'kubeview', 'kubernetes', 'exposure', 'kubeview_project', 'vkev', 'vuln'],
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
            'https://github.com/benc-uk/kubeview/issues/95',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-45933',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-45933',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Henry4E36/POCS',
        ],
        'cve': 'CVE-2022-45933',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/scrape/kube-system', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('BEGIN CERTIFICATE', 'END CERTIFICATE', 'kubernetes.io',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="KubeView <=0.1.31 - Information Disclosure detected",
                path='/api/scrape/kube-system',
            )
            return True
        return False

