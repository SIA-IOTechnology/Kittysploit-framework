#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gogs self-hosted Git service versions 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gogs <= 0.13.3 - Remote Code Execution Detection',
        'description': 'Gogs self-hosted Git service versions 0.13.3 and earlier contain a critical symlink bypass vulnerability that circumvents the fix for CVE-2024-55947. Authenticated users can exploit improper symbolic link handling in the PutContents API to overwrite files outside the repository by committing a symlink pointing to sensitive targets, leading to remote code execution. As of December 2025, this remains an unpatched zero-day with active exploitation ongoing. Approximately 1,400 exposed Gogs instances exist, with over 700 showing signs of compromise. The vulnerability stems from the API writing to file paths without checking if targets are symlinks pointing outside the repository. Gogs maintainers are working on a fix.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'modules': ['exploits/linux/http/gogs_cve_2025_8110_rce'],
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'gogs', 'git', 'symlink', 'rce', 'kev', 'vkev', 'passive'],
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
                        'capability': 'rce',
                        'from_detail': 'gogs symlink putcontents',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/linux/http/gogs_cve_2025_8110_rce',
                ],
            },
        },
        'references': [
            'https://www.wiz.io/blog/wiz-research-gogs-cve-2025-8110-rce-exploit',
            'https://thehackernews.com/2025/12/unpatched-gogs-zero-day-exploited.html',
            'https://github.com/advisories/ghsa-mq8m-42gh-wq7r',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-8110',
        ],
        'cve': 'CVE-2025-8110',
    }

    def run(self):
        path = '/user/login'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Sign In - Gogs: Go Git Service',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='high',
                reason='Gogs <= 0.13.3 - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

