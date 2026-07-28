#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""After the initial setup process, some steps of setup."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zabbix Setup Configuration Authentication Bypass Detection',
        'description': 'After the initial setup process, some steps of setup.php file are reachable not only by super-administrators but also by unauthenticated users. A malicious actor can pass step checks and potentially change the configuration of Zabbix Frontend.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'zabbix', 'auth-bypass', 'kev', 'vkev', 'vuln'],
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
            'https://blog.sonarsource.com/zabbix-case-study-of-unsafe-session-storage',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-23134',
            'https://support.zabbix.com/browse/ZBX-20384',
            'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/6SZYHXINBKCY42ITFSNCYE7KCSF33VRA/',
            'https://lists.debian.org/debian-lts-announce/2022/02/msg00008.html',
        ],
        'cve': 'CVE-2022-23134',
    }

    def run(self):
        for path in ('/zabbix/setup.php', '/setup.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('Database', 'host', 'port', 'Zabbix',)
            header_all = ('youtube_main', 'support.google.com',)
            if (all(m in body for m in body_all)) and (all(m in headers for m in header_all)):
                self.set_info(
                    severity='medium',
                    reason="Zabbix Setup Configuration Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

